#!/usr/bin/env python3
"""Independent stdlib-only verifier for Ed25519 Yao v1 vector corpora."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


VECTOR_CORPUS_SCHEMA_V1 = "seams:router-ab:ed25519-yao:vectors:v1"
KDF_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:kdf-continuity-vectors:v1"
)
LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:lifecycle-continuity-vectors:v1"
)
LIFECYCLE_CONTINUITY_EVIDENCE_SCOPE_V1 = "host_only_synthetic_continuity_v1"
PROVENANCE_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:role-input-provenance-vectors:v1"
)
PROVENANCE_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_proof_system_neutral_outer_contract_v1"
)
OUTPUT_SHARING_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:output-sharing-vectors:v1"
)
OUTPUT_SHARING_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_deterministic_output_sharing_v1"
)
CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:ceremony-context-vectors:v1"
)
CEREMONY_CONTEXT_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_public_ceremony_byte_contract_v1"
)
SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:semantic-artifact-lifecycle-vectors:v1"
)
SEMANTIC_LIFECYCLE_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_public_semantic_artifact_lifecycle_v1"
)
OUTPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:output-party-views-vectors:v1"
)
OUTPUT_PARTY_VIEWS_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_synthetic_output_party_views_v1"
)
EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:export-delivery-vectors:v1"
)
EXPORT_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1 = "host_only_synthetic_export_delivery_v1"
ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:activation-delivery-vectors:v1"
)
ACTIVATION_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_synthetic_activation_delivery_v1"
)
ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:activation-recipient-party-views:v1"
)
ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_synthetic_activation_recipient_party_views_v1"
)
EVALUATION_INPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:evaluation-input-party-views-vectors:v1"
)
EVALUATION_INPUT_PARTY_VIEWS_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_synthetic_evaluation_input_party_views_v1"
)
UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:uniform-abort-envelope-vectors:v1"
)
UNIFORM_ABORT_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_synthetic_uniform_abort_envelope_v1"
)
EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:evaluator-abort-state-party-views:v1"
)
EVALUATOR_ABORT_VIEW_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_synthetic_evaluator_abort_state_party_views_v1"
)
RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:recovery-credential-transition-vectors:v1"
)
RECOVERY_CREDENTIAL_TRANSITION_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_synthetic_recovery_credential_transition_v1"
)
EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:export-evaluator-authorization-vectors:v1"
)
EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_synthetic_export_evaluator_authorization_v1"
)
REGISTRATION_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:registration-evaluator-admission-vectors:v1"
)
REGISTRATION_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_construction_independent_registration_evaluator_admission_v1"
)
RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1 = (
    "seams:router-ab:ed25519-yao:recovery-evaluator-admission-vectors:v1"
)
RECOVERY_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1 = (
    "host_only_construction_independent_recovery_evaluator_admission_v1"
)
PROTOCOL_ID_V1 = "router_ab_ed25519_yao_v1"
STABLE_CONTEXT_DOMAIN_V1 = b"seams/router-ab/ed25519-yao/stable-key-context/v1"
STABLE_CONTEXT_BINDING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/stable-key-context-binding/v1"
)
APPLICATION_BINDING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/application-binding/v1"
)
APPLICATION_BINDING_WALLET_ID_LABEL_V1 = b"walletId"
APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1 = b"nearEd25519SigningKeyId"
APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1 = b"signingRootId"
APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1 = b"keyCreationSignerSlot"
DIFFERENTIAL_INPUT_DOMAIN_V1 = b"seams/router-ab/ed25519-yao/differential-input/v1"
MAX_DIFFERENTIAL_CASES_V1 = 4_096
CONTRIBUTION_KDF_EXTRACT_SALT_V1 = (
    b"seams/router-ab/ed25519-yao/contribution-kdf/hkdf-sha256/extract/v1"
)
CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/contribution-kdf/hkdf-sha256/expand/v1"
)
PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/provenance/stable-scope/v1"
)
PROVENANCE_CEREMONY_BINDING_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/provenance/ceremony-binding/v1"
)
PROVENANCE_ROLE_INPUT_SNAPSHOT_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/provenance/role-input-snapshot/v1"
)
PROVENANCE_REGISTRATION_BRANCH_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/provenance/registration-branch/v1"
)
PROVENANCE_RECOVERY_BRANCH_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/provenance/recovery-branch/v1"
)
PROVENANCE_REFRESH_BRANCH_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/provenance/refresh-branch/v1"
)
PROVENANCE_EXPORT_BRANCH_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/provenance/export-branch/v1"
)
PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/role-input-provenance-statement/v1"
)
PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/role-input-provenance-statement-digest/v1"
)
PROVENANCE_PAIR_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/role-input-provenance-pair/v1"
)
PROVENANCE_PAIR_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/role-input-provenance-pair-digest/v1"
)
PROVENANCE_CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/client-envelope-commitment-set/v1"
)
PROVENANCE_ARTIFACT_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/provenance-artifact-digest/v1"
)
ACTIVATION_CIRCUIT_ID_V1 = "ed25519_yao_activation_v1"
EXPORT_CIRCUIT_ID_V1 = "ed25519_yao_export_v1"
PUBLIC_REQUEST_CONTEXT_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/public-request-context/v1"
)
CEREMONY_TRANSCRIPT_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/ceremony-transcript/v1"
)
ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package/activation/deriver-a/client-scalar/v1"
)
ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package/activation/deriver-b/client-scalar/v1"
)
ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package/activation/deriver-a/signing-worker-scalar/v1"
)
ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package/activation/deriver-b/signing-worker-scalar/v1"
)
EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package/export/deriver-a/client-seed/v1"
)
EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package/export/deriver-b/client-seed/v1"
)
CLIENT_RECIPIENT_KEY_BINDING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-recipient-key-binding/client/v1"
)
SIGNING_WORKER_RECIPIENT_KEY_BINDING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-recipient-key-binding/signing-worker/v1"
)
SIGNING_WORKER_ACTIVATION_RECEIPT_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/signing-worker-activation-receipt/v1"
)
SIGNING_WORKER_ACTIVATION_RECEIPT_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/signing-worker-activation-receipt-digest/v1"
)
SIGNING_WORKER_RECEIPT_KEY_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/signing-worker-receipt-key-digest/v1"
)
STORE_AUTHORITY_KEY_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/store-authority-key-digest/v1"
)
EXPORT_AUTHORIZATION_ACCEPTANCE_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/export-authorization-acceptance/v1"
)
EXPORT_AUTHORIZATION_ACCEPTANCE_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/export-authorization-acceptance-digest/v1"
)
EXPORT_AUTHORIZATION_ACCEPTANCE_AUTHORITY_KEY_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/export-authorization-authority-key-digest/v1"
)
EXPORT_AUTHORIZATION_ACCEPTANCE_PAIR_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/export-authorization-acceptance-pair/v1"
)
EXPORT_AUTHORIZATION_ACCEPTANCE_PAIR_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/export-authorization-acceptance-pair-digest/v1"
)
STORE_IDENTITY_SCOPE_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/store-identity-scope/v1"
)
RECOVERY_PROMOTION_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/recovery-promotion/v1"
)
RECOVERY_PROMOTION_RECEIPT_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/recovery-promotion-receipt-digest/v1"
)
RECOVERY_PROMOTION_STATE_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/recovery-promotion-state-digest/v1"
)
RECOVERY_CREDENTIAL_TOMBSTONE_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/recovery-credential-tombstone-digest/v1"
)
ACTIVATION_RECIPIENT_TRUSTED_RECEIPT_AUTHORITIES_V1 = {
    "registration": (
        3,
        bytes.fromhex("af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d"),
    ),
    "recovery": (
        3,
        bytes.fromhex("2df04125f0015afb47ce853aef8772094ff9498c14cb1b9e12973c2927da0fa6"),
    ),
    "refresh": (
        3,
        bytes.fromhex("a7f6dfaf8f38b89ba8ce649b594f91e4d01fdc57f9c9493df43b5e50a9987367"),
    ),
}
ACTIVATION_PACKAGE_SET_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package-set/activation/v1"
)
ACTIVATION_PACKAGE_SET_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package-set/activation-digest/v1"
)
EXPORT_PACKAGE_SET_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package-set/export/v1"
)
EXPORT_PACKAGE_SET_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-package-set/export-digest/v1"
)
ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-receipt/activation-output-committed/v1"
)
ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-receipt/activation-output-committed-digest/v1"
)
REGISTRATION_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/registration-evaluator-admission/v1"
)
REGISTRATION_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/registration-evaluator-admission-digest/v1"
)
RECOVERY_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/recovery-evaluator-admission/v1"
)
RECOVERY_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/recovery-evaluator-admission-digest/v1"
)
AUTHENTICATED_STORE_RESOLUTION_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/authenticated-store-resolution/v1"
)
REGISTRATION_CANDIDATE_STATE_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/registration-candidate-state/v1"
)
REGISTRATION_CANDIDATE_STATE_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/registration-candidate-state-digest/v1"
)
EXPORT_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed/v1"
)
EXPORT_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed-digest/v1"
)
EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-receipt/export-released/v1"
)
EXPORT_RELEASED_RECEIPT_DIGEST_DOMAIN_V1 = (
    b"seams/router-ab/ed25519-yao/semantic-receipt/export-released-digest/v1"
)

REQUEST_KINDS = frozenset(
    {"registration", "activation", "recovery", "refresh", "export"}
)
REQUEST_KIND_CYCLE = ("registration", "activation", "recovery", "refresh", "export")
REFERENCE_KEYS = frozenset(
    {"case_id", "context", "inputs", "clear_reference_trace"}
)
CONTEXT_KEYS = frozenset(
    {
        "application_binding_digest_hex",
        "participant_ids",
        "encoded_hex",
        "binding_sha256_hex",
    }
)
INPUT_KEYS = frozenset(
    {
        "y_client_a_hex",
        "y_server_a_hex",
        "y_client_b_hex",
        "y_server_b_hex",
        "tau_client_a_hex",
        "tau_server_a_hex",
        "tau_client_b_hex",
        "tau_server_b_hex",
    }
)
TRACE_KEYS = frozenset(
    {
        "y_a_hex",
        "y_b_hex",
        "joined_seed_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "tau_a_hex",
        "tau_b_hex",
        "tau_hex",
        "x_client_base_hex",
        "x_server_base_hex",
        "x_client_point_hex",
        "x_server_point_hex",
        "public_key_hex",
    }
)
KDF_CASE_KEYS = frozenset(
    {
        "case_id",
        "application_binding",
        "synthetic_roots",
        "context",
        "contributions",
        "synthetic_clear_reference_trace",
    }
)
KDF_APPLICATION_BINDING_KEYS = frozenset(
    {
        "wallet_id",
        "near_ed25519_signing_key_id",
        "signing_root_id",
        "key_creation_signer_slot",
        "encoded_hex",
        "digest_sha256_hex",
    }
)
KDF_ROOT_KEYS = frozenset(
    {"client_root_hex", "deriver_a_root_hex", "deriver_b_root_hex"}
)

LIFECYCLE_CORPUS_KEY_ORDER = ("schema", "protocol_id", "evidence_scope", "cases")
LIFECYCLE_CASE_KEY_ORDER = ("request_kind", "vector")
LIFECYCLE_ACTIVATION_VECTOR_KEY_ORDER = ("origin_kind", "transition")
LIFECYCLE_APPLICATION_BINDING_KEY_ORDER = (
    "wallet_id",
    "near_ed25519_signing_key_id",
    "signing_root_id",
    "key_creation_signer_slot",
    "encoded_hex",
    "digest_sha256_hex",
)
LIFECYCLE_CONTEXT_KEY_ORDER = (
    "application_binding_digest_hex",
    "participant_ids",
    "encoded_hex",
    "binding_sha256_hex",
)
LIFECYCLE_IDENTITY_KEY_ORDER = (
    "application_binding",
    "context",
    "registered_public_key_hex",
    "x_client_point_hex",
    "x_server_point_hex",
)
LIFECYCLE_ROLE_EPOCH_KEY_ORDER = ("role_root_epoch", "role_input_state_epoch")
LIFECYCLE_ROLE_EPOCH_PAIR_KEY_ORDER = ("deriver_a", "deriver_b")
LIFECYCLE_ACTIVE_STATE_KEY_ORDER = (
    "identity",
    "active_role_epochs",
    "active_activation_epoch",
)
LIFECYCLE_REGISTRATION_PENDING_STATE_KEY_ORDER = (
    "identity",
    "candidate_role_epochs",
    "pending_activation_epoch",
)
LIFECYCLE_RECOVERY_PENDING_STATE_KEY_ORDER = (
    "identity",
    "current_role_epochs",
    "active_activation_epoch",
    "pending_activation_epoch",
)
LIFECYCLE_REFRESH_PENDING_STATE_KEY_ORDER = (
    "identity",
    "current_role_epochs",
    "next_role_epochs",
    "active_activation_epoch",
    "pending_activation_epoch",
    "derivation_admission",
)
LIFECYCLE_REFRESH_ACTIVATED_STATE_KEY_ORDER = (
    "identity",
    "active_role_epochs",
    "retired_role_input_state_epochs",
    "active_activation_epoch",
    "derivation_admission",
)
LIFECYCLE_RETIRED_EPOCH_KEY_ORDER = ("deriver_a", "deriver_b")
LIFECYCLE_OPERATION_COUNT_KEY_ORDER = (
    "deriver_a_invocations",
    "deriver_b_invocations",
    "client_kdf_derivations_a",
    "client_kdf_derivations_b",
    "server_kdf_derivations_a",
    "server_kdf_derivations_b",
    "activation_family_evaluations",
    "export_family_evaluations",
    "pending_activation_consumptions",
)
LIFECYCLE_ROOT_KEY_ORDER = (
    "client_root_hex",
    "deriver_a_root_hex",
    "deriver_b_root_hex",
)
LIFECYCLE_CONTRIBUTION_KEY_ORDER = (
    "y_client_a_hex",
    "tau_client_a_hex",
    "y_client_b_hex",
    "tau_client_b_hex",
    "y_server_a_hex",
    "tau_server_a_hex",
    "y_server_b_hex",
    "tau_server_b_hex",
)
LIFECYCLE_CLIENT_CONTRIBUTION_KEY_ORDER = (
    "y_client_a_hex",
    "tau_client_a_hex",
    "y_client_b_hex",
    "tau_client_b_hex",
)
LIFECYCLE_TRACE_KEY_ORDER = (
    "y_a_hex",
    "y_b_hex",
    "joined_seed_hex",
    "sha512_digest_hex",
    "clamped_scalar_bytes_hex",
    "signing_scalar_hex",
    "tau_a_hex",
    "tau_b_hex",
    "tau_hex",
    "x_client_base_hex",
    "x_server_base_hex",
    "x_client_point_hex",
    "x_server_point_hex",
    "public_key_hex",
)
LIFECYCLE_RECOVERY_HOST_KEY_ORDER = (
    "synthetic_roots",
    "current_contributions",
    "recovered_client_root_hex",
    "rederived_client_contributions",
    "after_contributions",
    "before_clear_reference_trace",
    "after_clear_reference_trace",
)
LIFECYCLE_REFRESH_DELTA_CONTRIBUTION_KEY_ORDER = ("delta_y_hex", "delta_tau_hex")
LIFECYCLE_REFRESH_DELTA_KEY_ORDER = (
    "deriver_a",
    "deriver_b",
    "combined_delta_y_hex",
    "combined_delta_tau_hex",
)
LIFECYCLE_REFRESH_HOST_KEY_ORDER = (
    "synthetic_roots",
    "before_contributions",
    "delta",
    "after_contributions",
    "before_clear_reference_trace",
    "after_clear_reference_trace",
)
LIFECYCLE_RECOVERY_VECTOR_KEY_ORDER = (
    "case_id",
    "before_public",
    "pending_public",
    "reference_operation_counts",
    "host_only_reference",
)
LIFECYCLE_REFRESH_VECTOR_KEY_ORDER = LIFECYCLE_RECOVERY_VECTOR_KEY_ORDER
LIFECYCLE_REGISTRATION_VECTOR_KEY_ORDER = (
    "case_id",
    "pending_public",
    "reference_operation_counts",
)
LIFECYCLE_ACTIVATION_TRANSITION_KEY_ORDER = (
    "case_id",
    "origin_case_id",
    "pending_public",
    "activated_public",
    "reference_operation_counts",
)

PROVENANCE_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "artifact_wrapper_goldens",
    "cases",
)
PROVENANCE_ARTIFACT_GOLDEN_KEY_ORDER = (
    "kind",
    "kind_tag",
    "canonical_artifact_hex",
    "digest_sha256_hex",
)
PROVENANCE_CASE_KEY_ORDER = ("request_kind", "vector")
PROVENANCE_VECTOR_KEY_ORDER = (
    "case_id",
    "circuit_family",
    "circuit_id",
    "final_circuit_digest_hex",
    "input_schema_digest_hex",
    "public_request_context_digest_hex",
    "transcript_digest_hex",
    "authorization_digest_hex",
    "client_envelope_a_artifact_digest_hex",
    "client_envelope_b_artifact_digest_hex",
    "client_envelope_set_digest_hex",
    "deriver_a",
    "deriver_b",
    "pair_encoding_hex",
    "pair_digest_sha256_hex",
)
PROVENANCE_ROLE_VECTOR_KEY_ORDER = (
    "role",
    "role_tag",
    "stable_scope_encoding_hex",
    "ceremony_binding_encoding_hex",
    "branch_encoding_hex",
    "snapshot_encodings_hex",
    "statement_encoding_hex",
    "statement_digest_sha256_hex",
)
PROVENANCE_ARTIFACT_SEQUENCE_V1 = (
    ("role_root_binding", 0x01),
    ("client_input_binding", 0x02),
    ("server_input_binding", 0x03),
    ("combined_role_input_binding", 0x04),
    ("client_envelope_commitment", 0x05),
    ("registration_anti_bias_evidence", 0x06),
    ("recovery_same_root_continuity", 0x07),
    ("refresh_opposite_delta_transition", 0x08),
)
PROVENANCE_CASE_SEQUENCE_V1 = (
    ("registration", "registration_provenance_outer_v1", 0x01),
    ("recovery", "recovery_provenance_outer_v1", 0x03),
    ("refresh", "refresh_provenance_outer_v1", 0x04),
    ("export", "export_provenance_outer_v1", 0x05),
)

OUTPUT_SHARING_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
OUTPUT_SHARING_CASE_KEY_ORDER = ("output_family", "vector")
OUTPUT_SHARING_ACTIVATION_VECTOR_KEY_ORDER = (
    "case_id",
    "request_kind",
    "host_only_source_reference",
    "host_only_joined_outputs",
    "host_only_reference_randomness",
    "role_output_shares",
)
OUTPUT_SHARING_EXPORT_VECTOR_KEY_ORDER = (
    "case_id",
    "host_only_source_reference",
    "host_only_joined_output",
    "host_only_reference_randomness",
    "role_output_shares",
)
OUTPUT_SHARING_SOURCE_REFERENCE_KEY_ORDER = ("case_id", "inputs")
OUTPUT_SHARING_INPUT_KEY_ORDER = (
    "y_client_a_hex",
    "y_server_a_hex",
    "y_client_b_hex",
    "y_server_b_hex",
    "tau_client_a_hex",
    "tau_server_a_hex",
    "tau_client_b_hex",
    "tau_server_b_hex",
)
OUTPUT_SHARING_ACTIVATION_JOINED_KEY_ORDER = (
    "x_client_base_hex",
    "x_server_base_hex",
)
OUTPUT_SHARING_ACTIVATION_RANDOMNESS_KEY_ORDER = (
    "r_client_hex",
    "r_signing_worker_hex",
)
OUTPUT_SHARING_ROLE_OUTPUT_KEY_ORDER = ("deriver_a", "deriver_b")
OUTPUT_SHARING_ACTIVATION_ROLE_SHARE_KEY_ORDER = (
    "client_scalar_share_hex",
    "signing_worker_scalar_share_hex",
)
OUTPUT_SHARING_EXPORT_JOINED_KEY_ORDER = ("joined_seed_hex",)
OUTPUT_SHARING_EXPORT_RANDOMNESS_KEY_ORDER = ("u_hex",)
OUTPUT_SHARING_EXPORT_ROLE_SHARE_KEY_ORDER = ("seed_share_hex",)
OUTPUT_SHARING_CASE_SEQUENCE_V1 = (
    (
        "activation",
        "registration_activation_shares_zero_coins_v1",
        "registration",
        "registration_rfc8032_vector_one_v1",
    ),
    (
        "activation",
        "recovery_activation_shares_small_coins_v1",
        "recovery",
        "recovery_clear_arithmetic_v1",
    ),
    (
        "activation",
        "refresh_activation_shares_boundary_coins_v1",
        "refresh",
        "refresh_clear_arithmetic_v1",
    ),
    (
        "export",
        "export_seed_shares_zero_coin_v1",
        None,
        "export_rfc8032_vector_two_v1",
    ),
    (
        "export",
        "export_seed_shares_one_coin_v1",
        None,
        "export_rfc8032_vector_two_v1",
    ),
    (
        "export",
        "export_seed_shares_max_coin_v1",
        None,
        "export_rfc8032_vector_two_v1",
    ),
)

CEREMONY_CONTEXT_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
CEREMONY_CONTEXT_CASE_KEY_ORDER = ("request_kind", "vector")
CEREMONY_CONTEXT_VECTOR_KEY_ORDER = (
    "case_id",
    "public_request_context",
    "authorization",
    "transcript",
    "expected",
)
CEREMONY_PUBLIC_REQUEST_CONTEXT_KEY_ORDER = (
    "protocol_version",
    "request_id",
    "replay_nonce_hex",
    "account_id",
    "wallet_id",
    "session_id",
    "organization_id",
    "project_id",
    "environment_id",
    "signing_root_id",
    "signing_root_version",
    "chain_target",
    "root_share_epoch",
    "router_id",
    "deriver_set_id",
    "deriver_a_id",
    "deriver_a_key_epoch",
    "deriver_b_id",
    "deriver_b_key_epoch",
    "signing_worker_id",
    "signing_worker_key_epoch",
    "client_ephemeral_public_key_hex",
    "recipient_plan",
    "output_package_kind",
    "request_expiry",
)
CEREMONY_TRANSCRIPT_INPUT_KEY_ORDER = (
    "transcript_nonce_hex",
    "transport_binding_digest_hex",
    "artifact_suite_digest_hex",
)
CEREMONY_EXPECTED_KEY_ORDER = (
    "public_request_context_encoding_hex",
    "public_request_context_digest_sha256_hex",
    "authorization_encoding_hex",
    "authorization_digest_sha256_hex",
    "transcript_encoding_hex",
    "transcript_digest_sha256_hex",
)
SEMANTIC_LIFECYCLE_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
SEMANTIC_LIFECYCLE_CASE_KEY_ORDER = ("request_kind", "vector")
SEMANTIC_LIFECYCLE_ACTIVATION_ARTIFACT_CASE_KEY_ORDER = (
    "case_id",
    "ceremony",
    "packages",
    "receipt",
    "persistence",
)
SEMANTIC_LIFECYCLE_EXPORT_CASE_KEY_ORDER = (
    "case_id",
    "ceremony",
    "packages",
    "receipt",
    "state_effect",
)
SEMANTIC_LIFECYCLE_CEREMONY_KEY_ORDER = (
    "public_request_context_encoding_hex",
    "public_request_context_digest_sha256_hex",
    "authorization_encoding_hex",
    "authorization_digest_sha256_hex",
    "transcript_encoding_hex",
    "transcript_digest_sha256_hex",
)
SEMANTIC_LIFECYCLE_ACTIVATION_PACKAGES_KEY_ORDER = (
    "deriver_a_client_descriptor_encoding_hex",
    "deriver_b_client_descriptor_encoding_hex",
    "deriver_a_signing_worker_descriptor_encoding_hex",
    "deriver_b_signing_worker_descriptor_encoding_hex",
    "package_set_encoding_hex",
    "package_set_digest_sha256_hex",
)
SEMANTIC_LIFECYCLE_EXPORT_PACKAGES_KEY_ORDER = (
    "deriver_a_client_descriptor_encoding_hex",
    "deriver_b_client_descriptor_encoding_hex",
    "package_set_encoding_hex",
    "package_set_digest_sha256_hex",
)
SEMANTIC_LIFECYCLE_RECEIPT_KEY_ORDER = (
    "receipt_body_encoding_hex",
    "receipt_body_digest_sha256_hex",
)
SEMANTIC_LIFECYCLE_ACTIVATION_CONTROL_KEY_ORDER = (
    "case_id",
    "metadata_consumed",
    "rejected_attempts",
)
SEMANTIC_LIFECYCLE_METADATA_CONSUMED_KEY_ORDER = (
    "origin_kind",
    "origin_case_id",
    "activation_ceremony",
    "persistence",
    "zero_reevaluation",
)
SEMANTIC_LIFECYCLE_REJECTED_ATTEMPT_KEY_ORDER = (
    "fixture_class",
    "fresh_fields",
    "persistence",
)
SEMANTIC_LIFECYCLE_FRESH_FIELDS_KEY_ORDER = (
    "request_id",
    "replay_nonce_hex",
    "request_expiry",
    "authorization_record_digest_hex",
    "transcript_nonce_hex",
    "transport_binding_digest_hex",
    "artifact_suite_digest_hex",
)
SEMANTIC_LIFECYCLE_ZERO_REEVALUATION_KEY_ORDER = (
    "yao_evaluations",
    "deriver_a_invocations",
    "deriver_b_invocations",
    "contribution_derivations",
    "output_share_samples",
)
SEMANTIC_LIFECYCLE_PERSISTENCE_KEY_ORDER = ("state", "projection")
SEMANTIC_LIFECYCLE_OUTPUT_COMMITTED_KEY_ORDER = ("identity",)
SEMANTIC_LIFECYCLE_ARTIFACT_IDENTITY_KEY_ORDER = (
    "origin_kind",
    "origin_request_kind",
    "origin_request_context_digest_hex",
    "origin_authorization_digest_hex",
    "origin_transcript_digest_hex",
    "one_use_execution_id_hex",
    "package_set_digest_hex",
    "receipt_digest_hex",
    "activation_epoch",
    "registered_public_key_hex",
)
SEMANTIC_LIFECYCLE_ATTEMPT_REJECTED_KEY_ORDER = ("before", "after", "abort")
SEMANTIC_LIFECYCLE_METADATA_PROJECTION_KEY_ORDER = (
    "committed",
    "activation_request_context_digest_hex",
    "activation_authorization_digest_hex",
    "activation_transcript_digest_hex",
)
SEMANTIC_LIFECYCLE_ABORT_KEY_ORDER = (
    "request_kind",
    "public_transcript_digest_hex",
    "public_failure_code",
    "terminal",
)
OUTPUT_PARTY_VIEWS_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
OUTPUT_PARTY_VIEWS_CASE_KEY_ORDER = ("request_kind", "vector")
OUTPUT_PARTY_VIEWS_VECTOR_KEY_ORDER = (
    "case_id",
    "stage",
    "common_public",
    "role_extensions",
    "static_deriver_observations",
)
OUTPUT_PARTY_VIEWS_ROLE_EXTENSIONS_KEY_ORDER = (
    "deriver_a",
    "deriver_b",
    "client",
    "signing_worker",
    "router",
    "observer",
    "diagnostics_logs",
)
OUTPUT_PARTY_VIEWS_STATIC_OBSERVATIONS_KEY_ORDER = ("deriver_a", "deriver_b")
OUTPUT_PARTY_VIEWS_STATIC_OBSERVATION_KEY_ORDER = (
    "observation_kind",
    "source_case_id",
    "source_stage",
    "extension",
)
OUTPUT_PARTY_VIEWS_ACTIVATION_SHARE_EXTENSION_KEY_ORDER = (
    "kind",
    "client_scalar_share_hex",
    "signing_worker_scalar_share_hex",
)
OUTPUT_PARTY_VIEWS_EXPORT_SHARE_EXTENSION_KEY_ORDER = ("kind", "seed_share_hex")
OUTPUT_PARTY_VIEWS_CLIENT_EXPORT_EXTENSION_KEY_ORDER = ("kind", "seed_hex")
OUTPUT_PARTY_VIEWS_EMPTY_EXTENSION_KEY_ORDER = ("kind",)
OUTPUT_PARTY_VIEWS_ACTIVATION_COMMON_KEY_ORDER = (
    "semantic_lifecycle_case_id",
    "stage",
    "request_kind",
    "circuit_id",
    "public_request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "transport_binding_digest_hex",
    "artifact_suite_digest_hex",
    "one_use_execution_id_hex",
    "input_provenance_pair_digest_hex",
    "host_reference_evaluation_evidence_digest_hex",
    "package_projection",
    "package_set_digest_hex",
    "receipt_body_digest_hex",
    "activation_epoch",
    "registered_public_key_hex",
    "x_client_hex",
    "x_server_hex",
    "deriver_a_receipt_evidence_digest_hex",
    "deriver_b_receipt_evidence_digest_hex",
    "terminal_state",
)
OUTPUT_PARTY_VIEWS_ACTIVATION_PACKAGE_PROJECTION_KEY_ORDER = (
    "deriver_a_client",
    "deriver_b_client",
    "deriver_a_signing_worker",
    "deriver_b_signing_worker",
)
OUTPUT_PARTY_VIEWS_ACTIVATION_PACKAGE_MEMBER_KEY_ORDER = (
    "role",
    "recipient",
    "output_family",
    "recipient_key_binding_hex",
    "share_point_hex",
    "recipient_protection_digest_hex",
    "recipient_ciphertext_digest_hex",
    "ciphertext_length",
    "output_binding_digest_hex",
    "package_authentication_digest_hex",
)
OUTPUT_PARTY_VIEWS_METADATA_COMMON_KEY_ORDER = (
    "semantic_lifecycle_case_id",
    "stage",
    "request_kind",
    "circuit_id",
    "origin_metadata_projections",
)
OUTPUT_PARTY_VIEWS_METADATA_PROJECTION_KEY_ORDER = (
    "origin_kind",
    "origin_case_id",
    "origin_request_context_digest_hex",
    "origin_authorization_digest_hex",
    "origin_transcript_digest_hex",
    "one_use_execution_id_hex",
    "package_set_digest_hex",
    "receipt_body_digest_hex",
    "activation_epoch",
    "registered_public_key_hex",
    "activation_request_context_digest_hex",
    "activation_authorization_digest_hex",
    "activation_transcript_digest_hex",
    "terminal_state",
    "zero_reevaluation",
)
OUTPUT_PARTY_VIEWS_EXPORT_COMMON_KEY_ORDER = (
    "semantic_lifecycle_case_id",
    "stage",
    "request_kind",
    "circuit_id",
    "public_request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "transport_binding_digest_hex",
    "artifact_suite_digest_hex",
    "one_use_execution_id_hex",
    "input_provenance_pair_digest_hex",
    "host_reference_evaluation_evidence_digest_hex",
    "package_projection",
    "package_set_digest_hex",
    "receipt_body_digest_hex",
    "registered_public_key_hex",
    "output_committed_receipt_digest_hex",
    "client_delivery_evidence_digest_hex",
    "export_authorization_consumption_evidence_digest_hex",
    "terminal_state",
    "state_effect",
)
OUTPUT_PARTY_VIEWS_EXPORT_PACKAGE_PROJECTION_KEY_ORDER = (
    "deriver_a_client",
    "deriver_b_client",
)
OUTPUT_PARTY_VIEWS_EXPORT_PACKAGE_MEMBER_KEY_ORDER = (
    "role",
    "recipient",
    "output_family",
    "recipient_key_binding_hex",
    "recipient_protection_digest_hex",
    "recipient_ciphertext_digest_hex",
    "ciphertext_length",
    "output_binding_digest_hex",
    "package_authentication_digest_hex",
)
EXPORT_DELIVERY_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
EXPORT_DELIVERY_CASE_KEY_ORDER = (
    "case_id",
    "request_kind",
    "semantic_lifecycle_case_id",
    "output_committed",
    "delivery_uncertain",
    "released",
    "redelivered",
)
EXPORT_DELIVERY_OUTPUT_COMMITTED_KEY_ORDER = (
    "request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "package_set_digest_hex",
    "output_committed_receipt_encoding_hex",
    "output_committed_receipt_digest_hex",
    "deriver_a_receipt_evidence_digest_hex",
    "deriver_b_receipt_evidence_digest_hex",
    "registered_public_key_hex",
    "active_state_version",
    "authorization_state",
)
EXPORT_DELIVERY_UNCERTAIN_KEY_ORDER = (
    "before_package_set_digest_hex",
    "after_package_set_digest_hex",
    "authorization_state",
    "zero_private_evaluation_work",
)
EXPORT_DELIVERY_RELEASED_KEY_ORDER = (
    "package_set_digest_hex",
    "output_committed_receipt_digest_hex",
    "released_receipt_encoding_hex",
    "released_receipt_digest_hex",
    "client_delivery_evidence_digest_hex",
    "consumed_authorization_evidence_digest_hex",
    "registered_public_key_hex",
    "active_state_version",
    "authorization_state",
    "client_seed_hex",
    "zero_private_evaluation_work",
)
EXPORT_DELIVERY_REDELIVERED_KEY_ORDER = (
    "before_released_receipt_digest_hex",
    "after_released_receipt_digest_hex",
    "client_seed_hex",
    "zero_private_evaluation_work",
)
EXPORT_DELIVERY_ZERO_WORK_KEY_ORDER = (
    "yao_evaluations",
    "deriver_a_invocations",
    "deriver_b_invocations",
    "contribution_derivations",
    "output_share_samples",
)
ACTIVATION_DELIVERY_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
ACTIVATION_DELIVERY_CASE_KEY_ORDER = (
    "case_id",
    "origin_request_kind",
    "semantic_lifecycle_case_id",
    "activation_semantic_lifecycle_case_id",
    "output_committed",
    "activation_control_admitted",
    "metadata_consumed",
    "delivery_uncertain",
    "recipients_released",
    "redelivered",
)
ACTIVATION_DELIVERY_OUTPUT_COMMITTED_KEY_ORDER = (
    "origin_request_context_digest_hex",
    "origin_authorization_digest_hex",
    "origin_transcript_digest_hex",
    "package_set_digest_hex",
    "output_committed_receipt_encoding_hex",
    "output_committed_receipt_digest_hex",
    "x_client_hex",
    "x_server_hex",
    "registered_public_key_hex",
    "activation_authorization_state",
)
ACTIVATION_DELIVERY_CONTROL_ADMITTED_KEY_ORDER = (
    "request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "package_set_digest_hex",
    "output_committed_receipt_digest_hex",
    "activation_authorization_state",
)
ACTIVATION_DELIVERY_METADATA_CONSUMED_KEY_ORDER = (
    "request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "package_set_digest_hex",
    "output_committed_receipt_digest_hex",
    "activation_authorization_state",
    "zero_private_evaluation_work",
)
ACTIVATION_DELIVERY_UNCERTAIN_KEY_ORDER = (
    "before_package_set_digest_hex",
    "after_package_set_digest_hex",
    "output_committed_receipt_digest_hex",
    "activation_transcript_digest_hex",
    "activation_authorization_state",
    "zero_private_evaluation_work",
)
ACTIVATION_DELIVERY_RELEASED_KEY_ORDER = (
    "package_set_digest_hex",
    "output_committed_receipt_digest_hex",
    "activation_transcript_digest_hex",
    "client",
    "signing_worker",
    "activation_authorization_state",
    "zero_private_evaluation_work",
)
ACTIVATION_DELIVERY_CLIENT_CAPABILITY_KEY_ORDER = (
    "capability_kind",
    "package_set_digest_hex",
    "delivery_evidence_digest_hex",
    "x_client_base_hex",
)
ACTIVATION_DELIVERY_WORKER_CAPABILITY_KEY_ORDER = (
    "capability_kind",
    "package_set_digest_hex",
    "delivery_evidence_digest_hex",
)
ACTIVATION_DELIVERY_REDELIVERED_KEY_ORDER = (
    "before_package_set_digest_hex",
    "after_package_set_digest_hex",
    "before_client_scalar_hex",
    "after_client_scalar_hex",
    "before_client_delivery_evidence_digest_hex",
    "after_client_delivery_evidence_digest_hex",
    "before_signing_worker_delivery_evidence_digest_hex",
    "after_signing_worker_delivery_evidence_digest_hex",
    "before_signing_worker_authority_package_set_digest_hex",
    "after_signing_worker_authority_package_set_digest_hex",
    "activation_authorization_state",
    "zero_private_evaluation_work",
)
ACTIVATION_DELIVERY_ZERO_WORK_KEY_ORDER = EXPORT_DELIVERY_ZERO_WORK_KEY_ORDER
ACTIVATION_RECIPIENT_VIEWS_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
ACTIVATION_RECIPIENT_VIEWS_CASE_KEY_ORDER = (
    "case_id",
    "origin_request_kind",
    "activation_delivery_case_id",
    "output_party_view_case_id",
    "recipients_released",
    "signing_worker_activated",
)
ACTIVATION_RECIPIENT_VIEWS_STAGE_KEY_ORDER = ("common_public", "role_extensions")
ACTIVATION_RECIPIENT_VIEWS_RELEASE_COMMON_KEY_ORDER = (
    "stage",
    "origin_request_kind",
    "package_set_digest_hex",
    "output_committed_receipt_digest_hex",
    "activation_transcript_digest_hex",
    "activation_authorization_state",
    "zero_private_evaluation_work",
)
ACTIVATION_RECIPIENT_VIEWS_ACTIVATED_COMMON_KEY_ORDER = (
    "stage",
    "origin_request_kind",
    "package_set_digest_hex",
    "output_committed_receipt_digest_hex",
    "activation_epoch",
    "signing_worker_id",
    "signing_worker_recipient_key_epoch",
    "registered_public_key_hex",
    "x_server_hex",
    "output_storage_evidence_digest_hex",
    "activation_receipt_encoding_hex",
    "activation_receipt_digest_hex",
    "activation_receipt_signature_hex",
    "receipt_key_epoch",
    "receipt_key_digest_hex",
    "receipt_verifying_key_hex",
    "activation_authorization_state",
)
ACTIVATION_RECIPIENT_VIEWS_ROLE_EXTENSIONS_KEY_ORDER = (
    "deriver_a",
    "deriver_b",
    "client",
    "signing_worker",
    "router",
    "observer",
    "diagnostics",
)
ACTIVATION_RECIPIENT_VIEWS_CLIENT_KEY_ORDER = (
    "extension_kind",
    "package_set_digest_hex",
    "delivery_evidence_digest_hex",
    "x_client_base_hex",
)
ACTIVATION_RECIPIENT_VIEWS_RELEASE_WORKER_KEY_ORDER = (
    "extension_kind",
    "package_set_digest_hex",
    "delivery_evidence_digest_hex",
)
ACTIVATION_RECIPIENT_VIEWS_ACTIVATED_WORKER_KEY_ORDER = (
    "extension_kind",
    "x_server_base_hex",
)
RECOVERY_TRANSITION_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
RECOVERY_TRANSITION_CASE_KEY_ORDER = (
    "case_id",
    "request_kind",
    "source_references",
    "suspended",
    "worker_activated",
    "promoted",
)
RECOVERY_TRANSITION_SOURCE_KEY_ORDER = (
    "ceremony_context_case_id",
    "provenance_case_id",
    "semantic_lifecycle_case_id",
    "activation_delivery_case_id",
    "activation_recipient_party_view_case_id",
)
RECOVERY_TRANSITION_SUSPENDED_KEY_ORDER = (
    "credential_state",
    "old_active_state_version",
    "old_credential_binding_digest_hex",
    "replacement_credential_binding_digest_hex",
    "same_root_evidence_artifact_digest_hex",
)
RECOVERY_TRANSITION_WORKER_ACTIVATED_KEY_ORDER = (
    "activation_receipt_digest_hex",
    "package_set_digest_hex",
    "output_committed_receipt_digest_hex",
    "worker_storage_receipt_digest_hex",
    "activation_epoch",
)
RECOVERY_TRANSITION_PROMOTED_KEY_ORDER = (
    "credential_state",
    "old_state",
    "next_state",
    "tombstone",
    "transaction_receipt_digest_hex",
    "promotion_receipt_encoding_hex",
    "promotion_receipt_digest_hex",
    "promotion_receipt_signature_hex",
)
RECOVERY_TRANSITION_STATE_KEY_ORDER = (
    "active_state_version",
    "registered_public_key_hex",
    "active_credential_binding_digest_hex",
    "stable_scope_encoding_hex",
    "active_activation_epoch",
    "deriver_a_root_record_hex",
    "deriver_a_root_binding_hex",
    "deriver_a_root_epoch",
    "deriver_a_state_record_hex",
    "deriver_a_input_state_epoch",
    "deriver_b_root_record_hex",
    "deriver_b_root_binding_hex",
    "deriver_b_root_epoch",
    "deriver_b_state_record_hex",
    "deriver_b_input_state_epoch",
)
RECOVERY_TRANSITION_TOMBSTONE_KEY_ORDER = (
    "credential_state",
    "credential_binding_digest_hex",
    "retired_state_version",
    "tombstone_digest_hex",
)
EXPORT_EVALUATOR_AUTHORIZATION_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
EXPORT_EVALUATOR_AUTHORIZATION_CASE_KEY_ORDER = (
    "case_id",
    "request_kind",
    "source_references",
    "common",
    "authorities",
    "acceptances",
    "accepted_pair",
    "evaluation",
)
EXPORT_EVALUATOR_AUTHORIZATION_SOURCE_KEY_ORDER = (
    "ceremony_context_case_id",
    "provenance_case_id",
    "evaluation_input_party_view_case_id",
    "semantic_lifecycle_case_id",
    "export_delivery_case_id",
)
EXPORT_EVALUATOR_AUTHORIZATION_COMMON_KEY_ORDER = (
    "request_id",
    "replay_nonce_hex",
    "request_expiry_unix_ms",
    "client_recipient_key_hex",
    "request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "provenance_pair_digest_hex",
    "signed_store_resolution_digest_hex",
    "store_authority_key_epoch",
    "store_authority_key_digest_hex",
    "active_state_version",
    "registered_public_key_hex",
    "one_use_execution_id_hex",
)
EXPORT_EVALUATOR_AUTHORIZATION_AUTHORITIES_KEY_ORDER = ("deriver_a", "deriver_b")
EXPORT_EVALUATOR_AUTHORIZATION_AUTHORITY_KEY_ORDER = (
    "role",
    "deriver_id",
    "key_epoch",
    "verifying_key_hex",
    "key_digest_hex",
)
EXPORT_EVALUATOR_AUTHORIZATION_ACCEPTANCES_KEY_ORDER = ("deriver_a", "deriver_b")
EXPORT_EVALUATOR_AUTHORIZATION_ACCEPTANCE_KEY_ORDER = (
    "role",
    "checked_at_unix_ms",
    "provenance_statement_digest_hex",
    "signing_bytes_hex",
    "signature_hex",
    "signed_artifact_digest_hex",
)
EXPORT_EVALUATOR_AUTHORIZATION_PAIR_KEY_ORDER = ("encoding_hex", "digest_hex")
EXPORT_EVALUATOR_AUTHORIZATION_EVALUATION_KEY_ORDER = (
    "evaluation_plan",
    "yao_evaluations",
    "deriver_a_invocations",
    "deriver_b_invocations",
    "output_committed_authorization_state",
    "output_committed_receipt_encoding_hex",
    "output_committed_receipt_digest_hex",
    "output_committed_evaluation_evidence_digest_hex",
    "released_authorization_state",
    "released_receipt_encoding_hex",
    "released_receipt_digest_hex",
    "released_evaluation_evidence_digest_hex",
    "registered_state_retained",
)
REGISTRATION_EVALUATOR_ADMISSION_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
REGISTRATION_EVALUATOR_ADMISSION_CASE_KEY_ORDER = (
    "case_id",
    "request_kind",
    "source_references",
    "admission",
    "evaluation",
    "retry",
    "claim_boundary",
)
REGISTRATION_EVALUATOR_ADMISSION_SOURCE_KEY_ORDER = (
    "ceremony_context_case_id",
    "provenance_case_id",
    "evaluation_input_party_view_case_id",
    "semantic_lifecycle_case_id",
    "output_party_view_case_id",
    "activation_delivery_case_id",
    "activation_recipient_party_view_case_id",
    "evaluator_abort_corpus_schema",
    "evaluator_abort_request_kind",
)
REGISTRATION_EVALUATOR_ADMISSION_KEY_ORDER = (
    "relation",
    "unregistered_public_identity_scope_encoding_hex",
    "request_id",
    "replay_nonce_hex",
    "request_expiry_unix_ms",
    "checked_at_unix_ms",
    "request_context_digest_hex",
    "authorization_record_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "registration_intent_digest_hex",
    "provenance_pair_digest_hex",
    "deriver_a_statement_digest_hex",
    "deriver_b_statement_digest_hex",
    "stable_scope_encoding_hex",
    "provenance_input_selection_artifact_digest_hex",
    "selected_mechanism_acceptance_evidence_digest_hex",
    "client_envelope_set_digest_hex",
    "deriver_a_initial_state",
    "deriver_b_initial_state",
    "activation_epoch",
    "one_use_execution_id_hex",
    "selection_attempt_id_hex",
    "selection_state",
    "encoding_hex",
    "digest_hex",
)
REGISTRATION_EVALUATOR_ADMISSION_ROLE_STATE_KEY_ORDER = (
    "role",
    "role_root_record_digest_hex",
    "root_binding_artifact_digest_hex",
    "role_root_epoch",
    "input_state_record_digest_hex",
    "input_state_epoch",
)
REGISTRATION_EVALUATOR_ADMISSION_EVALUATION_KEY_ORDER = (
    "evaluation_plan",
    "yao_evaluations",
    "deriver_a_invocations",
    "deriver_b_invocations",
    "contribution_derivations",
    "output_share_samples",
    "registered_public_key_hex",
    "package_set_digest_hex",
    "output_committed_receipt_encoding_hex",
    "output_committed_receipt_digest_hex",
    "output_committed_evaluation_evidence_digest_hex",
    "candidate_encoding_hex",
    "candidate_digest_hex",
    "candidate_output_committed_receipt_digest_hex",
    "pending_state",
    "terminal_selection_retained",
)
REGISTRATION_EVALUATOR_ADMISSION_RETRY_KEY_ORDER = (
    "accepted_selection_is_terminal",
    "evaluator_abort_preserves_public_state",
    "evaluator_abort_retains_terminal_selection",
    "retry_requires_fresh_execution",
    "retry_may_resample_selection",
)
REGISTRATION_EVALUATOR_ADMISSION_CLAIM_BOUNDARY_KEY_ORDER = (
    "unregistered_scope_claim",
    "provenance_input_selection_artifact_semantics",
    "selected_mechanism_acceptance_evidence_semantics",
    "excluded_claims",
)
RECOVERY_EVALUATOR_ADMISSION_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
RECOVERY_EVALUATOR_ADMISSION_CASE_KEY_ORDER = (
    "case_id",
    "request_kind",
    "source_references",
    "authenticated_store_resolution",
    "admission",
    "evaluation",
    "retry",
    "claim_boundary",
)
RECOVERY_EVALUATOR_ADMISSION_SOURCE_KEY_ORDER = (
    "ceremony_context_case_id",
    "provenance_case_id",
    "evaluation_input_party_view_case_id",
    "semantic_lifecycle_case_id",
    "output_party_view_case_id",
    "activation_delivery_case_id",
    "activation_recipient_party_view_case_id",
    "recovery_credential_transition_case_id",
    "evaluator_abort_corpus_schema",
    "evaluator_abort_request_kind",
)
RECOVERY_EVALUATOR_STORE_KEY_ORDER = (
    "signing_bytes_hex",
    "signing_bytes_sha256_hex",
    "authority_key_epoch",
    "authority_verifying_key_hex",
    "authority_key_digest_hex",
    "authority_signature_hex",
    "active_state_version",
    "registered_public_key_hex",
    "active_credential_binding_digest_hex",
    "stable_scope_encoding_hex",
    "active_activation_epoch",
    "deriver_a_root_record_digest_hex",
    "deriver_a_root_binding_artifact_digest_hex",
    "deriver_a_root_epoch",
    "deriver_a_input_state_record_digest_hex",
    "deriver_a_input_state_epoch",
    "deriver_b_root_record_digest_hex",
    "deriver_b_root_binding_artifact_digest_hex",
    "deriver_b_root_epoch",
    "deriver_b_input_state_record_digest_hex",
    "deriver_b_input_state_epoch",
)
RECOVERY_EVALUATOR_ADMISSION_KEY_ORDER = (
    "relation",
    "durable_identity_scope_encoding_hex",
    "request_id",
    "replay_nonce_hex",
    "request_expiry_unix_ms",
    "checked_at_unix_ms",
    "request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "provenance_pair_digest_hex",
    "deriver_a_statement_digest_hex",
    "deriver_b_statement_digest_hex",
    "active_credential_binding_digest_hex",
    "replacement_credential_binding_digest_hex",
    "registered_public_key_hex",
    "stable_scope_encoding_hex",
    "provenance_same_root_artifact_digest_hex",
    "selected_mechanism_acceptance_evidence_digest_hex",
    "current_activation_epoch",
    "next_activation_epoch",
    "one_use_execution_id_hex",
    "admission_state",
    "encoding_hex",
    "digest_hex",
)
RECOVERY_EVALUATOR_EVALUATION_KEY_ORDER = (
    "evaluation_plan",
    "yao_evaluations",
    "deriver_a_invocations",
    "deriver_b_invocations",
    "contribution_derivations",
    "output_share_samples",
    "registered_public_key_hex",
    "package_set_digest_hex",
    "output_committed_receipt_encoding_hex",
    "output_committed_receipt_digest_hex",
    "output_committed_evaluation_evidence_digest_hex",
    "pending_state",
    "old_credential_state",
    "terminal_admission_retained",
)
RECOVERY_EVALUATOR_RETRY_KEY_ORDER = (
    "evaluator_abort_preserves_public_state",
    "evaluator_abort_retains_terminal_admission",
    "evaluator_abort_retains_credential_suspension",
    "evaluator_abort_burns_execution",
    "retry_requires_fresh_authorization",
    "retry_requires_fresh_execution",
)
RECOVERY_EVALUATOR_CLAIM_KEY_ORDER = (
    "provenance_same_root_artifact_semantics",
    "selected_mechanism_acceptance_evidence_semantics",
    "excluded_claims",
)
EVALUATION_INPUT_PARTY_VIEWS_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
EVALUATION_INPUT_PARTY_VIEWS_CASE_KEY_ORDER = ("request_kind", "vector")
EVALUATION_INPUT_PARTY_VIEWS_VECTOR_KEY_ORDER = (
    "case_id",
    "stage",
    "host_only_source_references",
    "common_public",
    "role_extensions",
    "static_deriver_observations",
    "host_only_ideal_function_randomness",
)
EVALUATION_INPUT_PARTY_VIEWS_SOURCE_REFERENCES_KEY_ORDER = (
    "ceremony_context_case_id",
    "provenance_case_id",
    "semantic_lifecycle_case_id",
    "output_party_view_case_id",
)
EVALUATION_INPUT_PARTY_VIEWS_ACTIVATION_SOURCE_REFERENCES_KEY_ORDER = (
    "semantic_lifecycle_case_id",
    "output_party_view_case_id",
    "activation_origin",
)
EVALUATION_INPUT_PARTY_VIEWS_ROLE_EXTENSIONS_KEY_ORDER = (
    "deriver_a",
    "deriver_b",
    "client",
    "signing_worker",
    "router",
    "observer",
    "diagnostics_logs",
)
EVALUATION_INPUT_PARTY_VIEWS_STATIC_OBSERVATIONS_KEY_ORDER = (
    "deriver_a",
    "deriver_b",
)
EVALUATION_INPUT_PARTY_VIEWS_STATIC_OBSERVATION_KEY_ORDER = (
    "observation_kind",
    "source_case_id",
    "source_stage",
    "extension",
)
EVALUATION_INPUT_PARTY_VIEWS_COMMON_KEY_ORDER = (
    "stage",
    "request_kind",
    "evaluation_plan",
    "public_request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "input_provenance_pair_digest_hex",
)
EVALUATION_INPUT_PARTY_VIEWS_ACTIVATION_COMMON_KEY_ORDER = (
    "stage",
    "request_kind",
    "evaluation_plan",
    "public_request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
)
EVALUATION_INPUT_PARTY_VIEWS_EVALUATION_PLAN_KEY_ORDER = ("kind", "counts")
EVALUATION_INPUT_PARTY_VIEWS_EVALUATION_COUNTS_KEY_ORDER = (
    "yao_evaluations",
    "deriver_a_invocations",
    "deriver_b_invocations",
    "contribution_derivations",
    "ideal_output_share_samples",
)
EVALUATION_INPUT_PARTY_VIEWS_ACTIVATION_EXTENSION_KEY_ORDER = (
    "kind",
    "y_client_hex",
    "y_server_hex",
    "tau_client_hex",
    "tau_server_hex",
)
EVALUATION_INPUT_PARTY_VIEWS_EXPORT_EXTENSION_KEY_ORDER = (
    "kind",
    "y_client_hex",
    "y_server_hex",
)
EVALUATION_INPUT_PARTY_VIEWS_EMPTY_EXTENSION_KEY_ORDER = ("kind",)
EVALUATION_INPUT_PARTY_VIEWS_ACTIVATION_RANDOMNESS_KEY_ORDER = (
    "kind",
    "client_scalar_coin_hex",
    "signing_worker_scalar_coin_hex",
)
EVALUATION_INPUT_PARTY_VIEWS_NO_RANDOMNESS_KEY_ORDER = ("kind",)
EVALUATION_INPUT_PARTY_VIEWS_EXPORT_RANDOMNESS_KEY_ORDER = (
    "kind",
    "seed_output_coin_hex",
)
UNIFORM_ABORT_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
UNIFORM_ABORT_CASE_KEY_ORDER = (
    "request_kind",
    "source_ceremony_case_id",
    "envelope",
)
UNIFORM_ABORT_ENVELOPE_KEY_ORDER = (
    "request_kind",
    "public_transcript_digest_hex",
    "public_failure_code",
    "terminal",
)
EVALUATOR_ABORT_VIEW_CORPUS_KEY_ORDER = (
    "schema",
    "protocol_id",
    "evidence_scope",
    "cases",
)
EVALUATOR_ABORT_VIEW_CASE_KEY_ORDER = (
    "request_kind",
    "source_ceremony_case_id",
    "persistence",
    "party_views",
)
EVALUATOR_ABORT_PERSISTENCE_KEY_ORDER = (
    "pre_state_class",
    "transition",
    "burned_attempt",
    "public_abort",
)
EVALUATOR_ABORT_BURNED_ATTEMPT_KEY_ORDER = (
    "request_kind",
    "request_context_digest_hex",
    "authorization_digest_hex",
    "transcript_digest_hex",
    "one_use_execution_id_hex",
)
EVALUATOR_ABORT_PARTY_VIEWS_KEY_ORDER = (
    "deriver_a",
    "deriver_b",
    "client",
    "signing_worker",
    "router",
    "observer",
    "diagnostics",
)
CEREMONY_AUTHORIZATION_KEY_ORDERS = {
    "registration": (
        "authorization_record_digest_hex",
        "registration_intent_digest_hex",
    ),
    "activation": (
        "authorization_record_digest_hex",
        "origin_request_kind",
        "origin_request_context_digest_hex",
        "origin_transcript_digest_hex",
        "package_set_digest_hex",
        "activation_epoch",
    ),
    "recovery": (
        "authorization_record_digest_hex",
        "replacement_credential_binding_digest_hex",
    ),
    "refresh": (
        "authorization_record_digest_hex",
        "current_deriver_a_input_state_epoch",
        "next_deriver_a_input_state_epoch",
        "current_deriver_b_input_state_epoch",
        "next_deriver_b_input_state_epoch",
    ),
    "export": (
        "authorization_record_digest_hex",
        "registered_ed25519_public_key_hex",
    ),
}
CEREMONY_CASE_SEQUENCE_V1 = (
    ("registration", "ceremony-registration-v1", 0x01),
    ("activation", "ceremony-activation-v1", 0x02),
    ("recovery", "ceremony-recovery-v1", 0x03),
    ("refresh", "ceremony-refresh-v1", 0x04),
    ("export", "ceremony-export-v1", 0x05),
)
CEREMONY_KIND_METADATA_V1 = {
    "registration": (0x01, "activation_family", 0x01, "activation_scalar_shares", 0x01, ACTIVATION_CIRCUIT_ID_V1),
    "activation": (0x02, "activation_continuation", 0x02, "activation_scalar_shares", 0x01, ACTIVATION_CIRCUIT_ID_V1),
    "recovery": (0x03, "activation_family", 0x01, "activation_scalar_shares", 0x01, ACTIVATION_CIRCUIT_ID_V1),
    "refresh": (0x04, "activation_family", 0x01, "activation_scalar_shares", 0x01, ACTIVATION_CIRCUIT_ID_V1),
    "export": (0x05, "export", 0x03, "export_seed_shares", 0x02, EXPORT_CIRCUIT_ID_V1),
}
CEREMONY_AUTHORIZATION_DOMAINS_V1 = {
    kind: f"seams/router-ab/ed25519-yao/authorization/{kind}/v1".encode("ascii")
    for kind in REQUEST_KIND_CYCLE
}
SEMANTIC_LIFECYCLE_CASE_SEQUENCE_V1 = (
    "registration",
    "activation",
    "recovery",
    "refresh",
    "export",
)
SEMANTIC_LIFECYCLE_CASE_IDS_V1 = (
    "registration_semantic_artifacts_output_committed_v1",
    "activation_metadata_control_v1",
    "recovery_semantic_artifacts_output_committed_v1",
    "refresh_semantic_artifacts_output_committed_v1",
    "export_semantic_artifacts_host_reference_receipt_v1",
)
SEMANTIC_LIFECYCLE_ACTIVATION_ORIGINS_V1 = (
    "registration",
    "recovery",
    "refresh",
)
SEMANTIC_LIFECYCLE_REJECTION_CLASSES_V1 = (
    "request_id",
    "replay_nonce",
    "transcript_nonce",
    "origin_context_and_transcript",
)
OUTPUT_PARTY_VIEWS_CASE_SEQUENCE_V1 = (
    (
        "registration",
        "registration_output_party_views_package_prepared_v1",
        "registration_package_prepared",
        "registration_semantic_artifacts_output_committed_v1",
    ),
    (
        "activation",
        "activation_output_party_views_metadata_consumed_v1",
        "activation_metadata_consumed",
        "activation_metadata_control_v1",
    ),
    (
        "recovery",
        "recovery_output_party_views_package_prepared_v1",
        "recovery_package_prepared",
        "recovery_semantic_artifacts_output_committed_v1",
    ),
    (
        "refresh",
        "refresh_output_party_views_package_prepared_v1",
        "refresh_package_prepared",
        "refresh_semantic_artifacts_output_committed_v1",
    ),
    (
        "export",
        "export_output_party_views_released_v1",
        "export_released",
        "export_semantic_artifacts_host_reference_receipt_v1",
    ),
)
EVALUATION_INPUT_PARTY_VIEWS_CASE_SEQUENCE_V1 = (
    (
        "registration",
        "registration_evaluation_input_party_views_v1",
        "registration_evaluation_accepted",
    ),
    (
        "activation",
        "activation_no_evaluation_input_party_views_v1",
        "activation_continuation_accepted",
    ),
    (
        "recovery",
        "recovery_evaluation_input_party_views_v1",
        "recovery_evaluation_accepted",
    ),
    (
        "refresh",
        "refresh_evaluation_input_party_views_v1",
        "refresh_evaluation_accepted",
    ),
    (
        "export",
        "export_evaluation_input_party_views_v1",
        "export_evaluation_accepted",
    ),
)
EVALUATION_INPUT_PARTY_VIEWS_FORBIDDEN_KEYS_V1 = frozenset(
    {
        "client_root_hex",
        "deriver_a_root_hex",
        "deriver_b_root_hex",
        "recovered_client_root_hex",
        "role_root_hex",
        "root_hex",
        "joined_seed_hex",
        "joined_y_hex",
        "joined_tau_hex",
        "d_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "x_client_base_hex",
        "x_server_base_hex",
        "client_scalar_share_hex",
        "signing_worker_scalar_share_hex",
        "seed_share_hex",
        "seed_hex",
        "refresh_delta_y_hex",
        "refresh_delta_tau_hex",
        "credential_hex",
        "recovery_envelope_hex",
        "client_envelope_plaintext_hex",
        "ciphertext_bytes_hex",
        "recipient_decryption_key_hex",
        "garbling_seed_hex",
        "label_hex",
        "mask_hex",
        "ot_state_hex",
        "host_only_source_references",
        "host_only_ideal_function_randomness",
        "client_scalar_coin_hex",
        "signing_worker_scalar_coin_hex",
        "seed_output_coin_hex",
    }
)
EVALUATION_INPUT_PARTY_VIEWS_FORBIDDEN_KEY_SUFFIXES_V1 = (
    "_root",
    "_root_hex",
    "_coin_hex",
    "_output_share_hex",
    "_private_key_hex",
    "_decryption_key_hex",
)
OUTPUT_PARTY_VIEWS_FORBIDDEN_KEYS_V1 = frozenset(
    {
        "clear_reference_trace",
        "host_only_source_reference",
        "host_only_joined_output",
        "host_only_joined_outputs",
        "host_only_reference_randomness",
        "client_root_hex",
        "deriver_a_root_hex",
        "deriver_b_root_hex",
        "contributions",
        "joined_seed_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "tau_a_hex",
        "tau_b_hex",
        "tau_hex",
        "x_server_base_hex",
        "y_a_hex",
        "y_b_hex",
        "joined_y_hex",
        "refresh_delta_y_hex",
        "refresh_delta_tau_hex",
        "credential_hex",
        "recovery_envelope_hex",
        "ciphertext_bytes_hex",
        "recipient_decryption_key_hex",
        "garbling_seed_hex",
        "label_hex",
        "mask_hex",
        "ot_state_hex",
    }
)
OUTPUT_PARTY_VIEWS_FORBIDDEN_KEY_SUFFIXES_V1 = (
    "_coin_hex",
    "_root",
    "_root_hex",
    "_contribution",
    "_contribution_hex",
    "_private_key_hex",
    "_decryption_key_hex",
)
SEMANTIC_LIFECYCLE_REQUEST_CONTEXT_LABELS_V1 = (
    b"protocolVersion",
    b"requestKind",
    b"requestId",
    b"replayNonce",
    b"accountId",
    b"walletId",
    b"sessionId",
    b"organizationId",
    b"projectId",
    b"environmentId",
    b"signingRootId",
    b"signingRootVersion",
    b"chainTarget",
    b"rootShareEpoch",
    b"routerId",
    b"deriverSetId",
    b"deriverAId",
    b"deriverAKeyEpoch",
    b"deriverBId",
    b"deriverBKeyEpoch",
    b"signingWorkerId",
    b"signingWorkerKeyEpoch",
    b"clientEphemeralPublicKey",
    b"recipientPlan",
    b"outputPackageKind",
    b"requestExpiry",
)
SEMANTIC_LIFECYCLE_AUTHORIZATION_LABELS_V1 = {
    "registration": (
        b"requestKind",
        b"publicRequestContextDigest",
        b"authorizationRecordDigest",
        b"registrationIntentDigest",
    ),
    "activation": (
        b"requestKind",
        b"publicRequestContextDigest",
        b"authorizationRecordDigest",
        b"originRequestKind",
        b"originRequestContextDigest",
        b"originTranscriptDigest",
        b"packageSetDigest",
        b"activationEpoch",
    ),
    "recovery": (
        b"requestKind",
        b"publicRequestContextDigest",
        b"authorizationRecordDigest",
        b"replacementCredentialBindingDigest",
    ),
    "refresh": (
        b"requestKind",
        b"publicRequestContextDigest",
        b"authorizationRecordDigest",
        b"currentDeriverAInputStateEpoch",
        b"nextDeriverAInputStateEpoch",
        b"currentDeriverBInputStateEpoch",
        b"nextDeriverBInputStateEpoch",
    ),
    "export": (
        b"requestKind",
        b"publicRequestContextDigest",
        b"authorizationRecordDigest",
        b"registeredEd25519PublicKey",
    ),
}
SEMANTIC_LIFECYCLE_TRANSCRIPT_LABELS_V1 = (
    b"protocolVersion",
    b"protocolId",
    b"requestKind",
    b"circuitId",
    b"publicRequestContextDigest",
    b"authorizationDigest",
    b"transcriptNonce",
    b"transportBindingDigest",
    b"artifactSuiteDigest",
)
SEMANTIC_LIFECYCLE_FORBIDDEN_FIELD_FRAGMENTS_V1 = (
    "synthetic_root",
    "contribution_hex",
    "joined_secret",
    "joined_seed",
    "output_coin",
    "scalar_share",
    "seed_share",
    "refresh_delta",
    "delta_y",
    "delta_tau",
    "ciphertext_bytes",
    "sha512_digest",
    "clamped_scalar",
    "signing_scalar",
    "x_client_base",
    "x_server_base",
)

LIFECYCLE_CASE_SEQUENCE_V1 = (
    ("registration", "registration_candidate_metadata_v1"),
    ("activation", "activation_after_registration_zero_evaluation_v1"),
    ("recovery", "recovery_same_root_continuity_v1"),
    ("activation", "activation_after_recovery_zero_evaluation_v1"),
    ("refresh", "refresh_opposite_delta_continuity_v1"),
    ("activation", "activation_after_refresh_zero_evaluation_v1"),
)
LIFECYCLE_ACTIVATION_ORIGIN_KIND_BY_CASE_ID_V1 = {
    "activation_after_registration_zero_evaluation_v1": "registration",
    "activation_after_recovery_zero_evaluation_v1": "recovery",
    "activation_after_refresh_zero_evaluation_v1": "refresh",
}
LIFECYCLE_ORIGIN_CASE_ID_BY_KIND_V1 = {
    "registration": "registration_candidate_metadata_v1",
    "recovery": "recovery_same_root_continuity_v1",
    "refresh": "refresh_opposite_delta_continuity_v1",
}
LIFECYCLE_WALLET_ID_V1 = "wallet-fixture"
LIFECYCLE_SIGNING_KEY_ID_V1 = "ed25519ks_fixture"
LIFECYCLE_SIGNING_ROOT_ID_V1 = "project-fixture:env-fixture"
LIFECYCLE_KEY_CREATION_SIGNER_SLOT_V1 = 1
LIFECYCLE_CLIENT_ROOT_V1 = bytes((0x11,)) * 32
LIFECYCLE_DERIVER_A_ROOT_V1 = bytes((0x22,)) * 32
LIFECYCLE_DERIVER_B_ROOT_V1 = bytes((0x33,)) * 32
LIFECYCLE_DELTA_Y_V1 = bytes((0xA5,)) * 32
LIFECYCLE_DELTA_TAU_V1 = 17
LIFECYCLE_PUBLIC_KEY_V1 = bytes.fromhex(
    "ccd255d0b88721771947038f1a7c29b49eee3902d6aa732e5e448251537bf077"
)
LIFECYCLE_X_CLIENT_POINT_V1 = bytes.fromhex(
    "51b3df90f4b138f15cce318f39b790972440dc6a22122e52839dc83513006b72"
)
LIFECYCLE_X_SERVER_POINT_V1 = bytes.fromhex(
    "4809448a1ab1912ec0f4664194d9a6ad23b93ac4c348c4028c760a3c641f0e02"
)
LIFECYCLE_PUBLIC_FORBIDDEN_SUFFIXES_V1 = (
    "_root_hex",
    "_contribution_hex",
    "_delta_hex",
    "joined_seed_hex",
    "sha512_digest_hex",
    "clamped_scalar_bytes_hex",
    "signing_scalar_hex",
    "x_client_base_hex",
    "x_server_base_hex",
    "authorized_seed_hex",
)

LOWER_HEX = re.compile(r"[0-9a-f]+\Z")
FIELD_PRIME = (1 << 255) - 19
SCALAR_ORDER = (1 << 252) + 27742317777372353535851937790883648493
SEED_MODULUS_MASK = (1 << 256) - 1
OUTPUT_SHARING_ACTIVATION_COINS_V1 = (
    (0, 0),
    (1, 2),
    (SCALAR_ORDER - 1, SCALAR_ORDER - 2),
)
OUTPUT_SHARING_EXPORT_COINS_V1 = (0, 1, SEED_MODULUS_MASK)
OUTPUT_SHARING_SOURCE_INPUTS_V1 = {
    "registration_rfc8032_vector_one_v1": (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "00" * 32,
        "00" * 32,
        "00" * 32,
        "00" * 32,
        "00" * 32,
        "00" * 32,
        "00" * 32,
    ),
    "recovery_clear_arithmetic_v1": (
        "131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ec",
        "293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f405162738",
        "96afc8e1fa132c455e7790a9c2dbf40d263f58718aa3bcd5ee072039526b849d",
        "7093b6d9fc1f426588abcef114375a7da0c3e6092c4f7295b8dbfe2144678aad",
        "03" + "00" * 31,
        "05" + "00" * 31,
        "09" + "00" * 31,
        "0f" + "00" * 31,
    ),
    "refresh_clear_arithmetic_v1": (
        "71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a",
        "1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c",
        "f40d263f58718aa3bcd5ee072039526b849db6cfe8011a334c657e97b0c9e2fb",
        "6487aacdf01336597c9fc2e5082b4e7194b7dafd20436689accff215385b7ea1",
        "13" + "00" * 31,
        "15" + "00" * 31,
        "19" + "00" * 31,
        "1f" + "00" * 31,
    ),
    "export_rfc8032_vector_two_v1": (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "00" * 32,
        "00" * 32,
        "00" * 32,
        "05" + "00" * 31,
        "07" + "00" * 31,
        "0b" + "00" * 31,
        "0d" + "00" * 31,
    ),
}


class VerificationError(ValueError):
    """A corpus or vector failed strict independent verification."""


Point = tuple[int, int, int, int]


def _field_inverse(value: int) -> int:
    return pow(value, FIELD_PRIME - 2, FIELD_PRIME)


def _recover_base_x(base_y: int) -> int:
    curve_d = (-121665 * _field_inverse(121666)) % FIELD_PRIME
    y_squared = (base_y * base_y) % FIELD_PRIME
    x_squared = ((y_squared - 1) * _field_inverse(curve_d * y_squared + 1)) % FIELD_PRIME
    base_x = pow(x_squared, (FIELD_PRIME + 3) // 8, FIELD_PRIME)
    if (base_x * base_x - x_squared) % FIELD_PRIME != 0:
        sqrt_minus_one = pow(2, (FIELD_PRIME - 1) // 4, FIELD_PRIME)
        base_x = (base_x * sqrt_minus_one) % FIELD_PRIME
    if (base_x * base_x - x_squared) % FIELD_PRIME != 0:
        raise RuntimeError("the RFC 8032 base point has no field square root")
    if base_x & 1:
        base_x = FIELD_PRIME - base_x
    return base_x


CURVE_D = (-121665 * _field_inverse(121666)) % FIELD_PRIME
BASE_Y = (4 * _field_inverse(5)) % FIELD_PRIME
BASE_X = _recover_base_x(BASE_Y)
IDENTITY_POINT: Point = (0, 1, 1, 0)
BASE_POINT: Point = (BASE_X, BASE_Y, 1, (BASE_X * BASE_Y) % FIELD_PRIME)


def _point_add(left: Point, right: Point) -> Point:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % FIELD_PRIME
    b = ((y1 + x1) * (y2 + x2)) % FIELD_PRIME
    c = (2 * CURVE_D * t1 * t2) % FIELD_PRIME
    d = (2 * z1 * z2) % FIELD_PRIME
    e = (b - a) % FIELD_PRIME
    f = (d - c) % FIELD_PRIME
    g = (d + c) % FIELD_PRIME
    h = (b + a) % FIELD_PRIME
    return (
        (e * f) % FIELD_PRIME,
        (g * h) % FIELD_PRIME,
        (f * g) % FIELD_PRIME,
        (e * h) % FIELD_PRIME,
    )


def _point_double(point: Point) -> Point:
    x, y, z, _ = point
    a = (x * x) % FIELD_PRIME
    b = (y * y) % FIELD_PRIME
    c = (2 * z * z) % FIELD_PRIME
    d = (-a) % FIELD_PRIME
    e = ((x + y) * (x + y) - a - b) % FIELD_PRIME
    g = (d + b) % FIELD_PRIME
    f = (g - c) % FIELD_PRIME
    h = (d - b) % FIELD_PRIME
    return (
        (e * f) % FIELD_PRIME,
        (g * h) % FIELD_PRIME,
        (f * g) % FIELD_PRIME,
        (e * h) % FIELD_PRIME,
    )


def _multiply_base(scalar: int) -> Point:
    if scalar < 0 or scalar >= 1 << 255:
        raise VerificationError("internal Ed25519 scalar is outside the 255-bit range")
    result = IDENTITY_POINT
    addend = BASE_POINT
    for bit_index in range(255):
        if scalar & (1 << bit_index):
            result = _point_add(result, addend)
        addend = _point_double(addend)
    return result


def _multiply_point(point: Point, scalar: int) -> Point:
    if scalar < 0 or scalar >= 1 << 256:
        raise VerificationError("internal Edwards25519 scalar is outside the 256-bit range")
    result = IDENTITY_POINT
    addend = point
    for bit_index in range(256):
        if scalar & (1 << bit_index):
            result = _point_add(result, addend)
        addend = _point_double(addend)
    return result


def _compress_point(point: Point) -> bytes:
    x, y, z, _ = point
    inverse_z = _field_inverse(z)
    affine_x = (x * inverse_z) % FIELD_PRIME
    affine_y = (y * inverse_z) % FIELD_PRIME
    encoded = affine_y | ((affine_x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _decompress_point(encoded: bytes, path: str) -> Point:
    if len(encoded) != 32:
        raise VerificationError(f"{path} must contain exactly 32 bytes")
    encoded_integer = int.from_bytes(encoded, "little")
    sign = encoded_integer >> 255
    affine_y = encoded_integer & ((1 << 255) - 1)
    if affine_y >= FIELD_PRIME:
        raise VerificationError(f"{path} is a noncanonical Edwards25519 encoding")
    y_squared = affine_y * affine_y % FIELD_PRIME
    denominator = (CURVE_D * y_squared + 1) % FIELD_PRIME
    if denominator == 0:
        raise VerificationError(f"{path} is not an Edwards25519 point")
    x_squared = (y_squared - 1) * _field_inverse(denominator) % FIELD_PRIME
    affine_x = pow(x_squared, (FIELD_PRIME + 3) // 8, FIELD_PRIME)
    if (affine_x * affine_x - x_squared) % FIELD_PRIME != 0:
        sqrt_minus_one = pow(2, (FIELD_PRIME - 1) // 4, FIELD_PRIME)
        affine_x = affine_x * sqrt_minus_one % FIELD_PRIME
    if (affine_x * affine_x - x_squared) % FIELD_PRIME != 0:
        raise VerificationError(f"{path} is not an Edwards25519 point")
    if affine_x & 1 != sign:
        affine_x = FIELD_PRIME - affine_x
    point = (affine_x, affine_y, 1, affine_x * affine_y % FIELD_PRIME)
    if _compress_point(point) != encoded:
        raise VerificationError(f"{path} is a noncanonical Edwards25519 encoding")
    return point


def _points_equal(left: Point, right: Point) -> bool:
    left_x, left_y, left_z, _ = left
    right_x, right_y, right_z, _ = right
    return (
        (left_x * right_z - right_x * left_z) % FIELD_PRIME == 0
        and (left_y * right_z - right_y * left_z) % FIELD_PRIME == 0
    )


def _negate_point(point: Point) -> Point:
    x, y, z, t = point
    return ((-x) % FIELD_PRIME, y, z, (-t) % FIELD_PRIME)


def _require_point_addition(
    left_encoded: bytes,
    right_encoded: bytes,
    expected_encoded: bytes,
    path: str,
) -> None:
    left = _decompress_point(left_encoded, f"{path}.left")
    right = _decompress_point(right_encoded, f"{path}.right")
    expected = _decompress_point(expected_encoded, f"{path}.expected")
    if not _points_equal(_point_add(left, right), expected):
        raise VerificationError(f"{path} does not equal the Edwards25519 point sum")


def _require_activation_public_relation(
    x_client_encoded: bytes,
    x_server_encoded: bytes,
    registered_public_key_encoded: bytes,
    path: str,
) -> None:
    x_client = _decompress_point(x_client_encoded, f"{path}.x_client")
    x_server = _decompress_point(x_server_encoded, f"{path}.x_server")
    registered_public_key = _decompress_point(
        registered_public_key_encoded, f"{path}.registered_public_key"
    )
    if _points_equal(x_client, IDENTITY_POINT):
        raise VerificationError(f"{path}.x_client must not be the identity")
    if _points_equal(x_server, IDENTITY_POINT):
        raise VerificationError(f"{path}.x_server must not be the identity")
    _verify_registered_public_key(
        registered_public_key_encoded, f"{path}.registered_public_key"
    )
    derived = _point_add(_point_double(x_client), _negate_point(x_server))
    if not _points_equal(derived, registered_public_key):
        raise VerificationError(
            f"{path} violates 2*X_client-X_server=A_pub"
        )


def _verify_registered_public_key(encoded: bytes, path: str) -> None:
    point = _require_prime_order_subgroup_point(encoded, path)
    if _points_equal(point, IDENTITY_POINT):
        raise VerificationError(f"{path} must not be the Edwards25519 identity")


def _require_prime_order_subgroup_point(encoded: bytes, path: str) -> Point:
    point = _decompress_point(encoded, path)
    if not _points_equal(_multiply_point(point, SCALAR_ORDER), IDENTITY_POINT):
        raise VerificationError(f"{path} must be in the prime-order subgroup")
    return point


if _compress_point(BASE_POINT).hex() != (
    "5866666666666666666666666666666666666666666666666666666666666666"
):
    raise RuntimeError("independent Edwards25519 base-point construction failed")


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise VerificationError(f"duplicate JSON object key {key!r}")
        output[key] = value
    return output


def _reject_json_constant(value: str) -> None:
    raise VerificationError(f"non-standard JSON constant {value!r}")


def parse_corpus_json(encoded: str) -> dict[str, Any]:
    """Parses JSON while rejecting duplicate keys and non-standard numbers."""
    try:
        decoded = json.loads(
            encoded,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise VerificationError(f"invalid JSON: {error}") from error
    return _require_object(decoded, "$")


def load_corpus(path: Path | str) -> dict[str, Any]:
    """Loads one UTF-8 vector corpus from disk with strict JSON parsing."""
    corpus_path = Path(path)
    try:
        encoded_bytes = corpus_path.read_bytes()
        encoded = encoded_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise VerificationError(f"cannot read {corpus_path}: {error}") from error
    corpus = parse_corpus_json(encoded)
    if corpus.get("schema") in {
        OUTPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
        ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
        EVALUATION_INPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
        UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1,
        EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1,
    }:
        canonical = (json.dumps(corpus, ensure_ascii=False, indent=2) + "\n").encode(
            "utf-8"
        )
        if encoded_bytes != canonical:
            raise VerificationError(
                f"{corpus_path} is not canonical pretty JSON with exactly one trailing LF"
            )
    return corpus


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise VerificationError(f"{path} must be a JSON object")
    return value


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{path} must be an array")
    return value


def _require_exact_keys(value: Any, expected: Iterable[str], path: str) -> dict[str, Any]:
    object_value = _require_object(value, path)
    expected_keys = set(expected)
    actual_keys = set(object_value)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        unexpected = sorted(actual_keys - expected_keys)
        raise VerificationError(
            f"{path} has invalid keys; missing={missing}, unexpected={unexpected}"
        )
    return object_value


def _require_ordered_keys(
    value: Any, expected: Sequence[str], path: str
) -> dict[str, Any]:
    object_value = _require_exact_keys(value, expected, path)
    actual_order = tuple(object_value)
    expected_order = tuple(expected)
    if actual_order != expected_order:
        raise VerificationError(
            f"{path} has noncanonical key order; "
            f"expected={list(expected_order)}, actual={list(actual_order)}"
        )
    return object_value


def _require_string(value: Any, path: str) -> str:
    if type(value) is not str:
        raise VerificationError(f"{path} must be a string")
    return value


def _decode_hex(value: Any, byte_length: int, path: str) -> bytes:
    encoded = _require_string(value, path)
    if len(encoded) != byte_length * 2 or LOWER_HEX.fullmatch(encoded) is None:
        raise VerificationError(
            f"{path} must be exactly {byte_length} lowercase hexadecimal bytes"
        )
    return bytes.fromhex(encoded)


def _decode_variable_hex(value: Any, path: str) -> bytes:
    encoded = _require_string(value, path)
    if len(encoded) % 2 != 0 or (encoded and LOWER_HEX.fullmatch(encoded) is None):
        raise VerificationError(f"{path} must contain lowercase hexadecimal bytes")
    return bytes.fromhex(encoded)


def _decode_scalar(value: Any, path: str) -> int:
    encoded = _decode_hex(value, 32, path)
    scalar = int.from_bytes(encoded, "little")
    if scalar >= SCALAR_ORDER:
        raise VerificationError(f"{path} must encode a canonical Ed25519 scalar")
    return scalar


def _require_expected_bytes(value: Any, expected: bytes, path: str) -> None:
    actual = _decode_hex(value, len(expected), path)
    if actual != expected:
        raise VerificationError(f"{path} does not match the independently computed value")


def _length_prefix_u32(value: bytes) -> bytes:
    if len(value) > 0xFFFF_FFFF:
        raise VerificationError("application-binding value exceeds its U32 length prefix")
    return len(value).to_bytes(4, "big") + value


def _lp32_join(fields: Sequence[bytes]) -> bytes:
    return b"".join(_length_prefix_u32(field) for field in fields)


def _digest_encoding(domain: bytes, encoding: bytes) -> bytes:
    return hashlib.sha256(_lp32_join((domain, encoding))).digest()


def _parse_lp32_fields(encoded: bytes, expected_count: int, path: str) -> tuple[bytes, ...]:
    fields: list[bytes] = []
    offset = 0
    while offset < len(encoded):
        length_end = offset + 4
        if length_end > len(encoded):
            raise VerificationError(f"{path} has a truncated LP32 length")
        length = int.from_bytes(encoded[offset:length_end], "big")
        value_end = length_end + length
        if value_end > len(encoded):
            raise VerificationError(f"{path} has a truncated LP32 value")
        fields.append(encoded[length_end:value_end])
        offset = value_end
    if offset != len(encoded):
        raise VerificationError(f"{path} has trailing bytes")
    if len(fields) != expected_count:
        raise VerificationError(
            f"{path} must contain exactly {expected_count} LP32 fields"
        )
    return tuple(fields)


def _require_bytes(actual: bytes, expected: bytes, path: str) -> None:
    if actual != expected:
        raise VerificationError(f"{path} does not match the frozen value")


def _require_fixed_bytes(actual: bytes, byte_length: int, path: str) -> bytes:
    if len(actual) != byte_length:
        raise VerificationError(f"{path} must contain exactly {byte_length} bytes")
    return actual


def _canonical_application_identifier(value: Any, path: str) -> bytes:
    identifier = _require_string(value, path)
    if not identifier:
        raise VerificationError(f"{path} must be nonempty")
    try:
        encoded = identifier.encode("utf-8")
    except UnicodeEncodeError as error:
        raise VerificationError(f"{path} must contain valid Unicode scalar values") from error
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise VerificationError(f"{path} must contain only visible ASCII bytes")
    return encoded


def _canonical_application_signer_slot(value: Any, path: str) -> bytes:
    if type(value) is not int or not 1 <= value <= 0xFFFF_FFFF:
        raise VerificationError(f"{path} must be a positive u32")
    return value.to_bytes(4, "big")


def _verify_application_binding(binding: Any, path: str) -> bytes:
    binding_object = _require_exact_keys(binding, KDF_APPLICATION_BINDING_KEYS, path)
    wallet_id = _canonical_application_identifier(
        binding_object["wallet_id"], f"{path}.wallet_id"
    )
    signing_key_id = _canonical_application_identifier(
        binding_object["near_ed25519_signing_key_id"],
        f"{path}.near_ed25519_signing_key_id",
    )
    signing_root_id = _canonical_application_identifier(
        binding_object["signing_root_id"], f"{path}.signing_root_id"
    )
    key_creation_signer_slot = _canonical_application_signer_slot(
        binding_object["key_creation_signer_slot"],
        f"{path}.key_creation_signer_slot",
    )
    encoded = b"".join(
        (
            _length_prefix_u32(APPLICATION_BINDING_DOMAIN_V1),
            _length_prefix_u32(APPLICATION_BINDING_WALLET_ID_LABEL_V1),
            _length_prefix_u32(wallet_id),
            _length_prefix_u32(APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1),
            _length_prefix_u32(signing_key_id),
            _length_prefix_u32(APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1),
            _length_prefix_u32(signing_root_id),
            _length_prefix_u32(APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1),
            _length_prefix_u32(key_creation_signer_slot),
        )
    )
    _require_expected_bytes(binding_object["encoded_hex"], encoded, f"{path}.encoded_hex")
    digest = hashlib.sha256(encoded).digest()
    _require_expected_bytes(
        binding_object["digest_sha256_hex"], digest, f"{path}.digest_sha256_hex"
    )
    return digest


def _encode_scalar(scalar: int) -> bytes:
    return (scalar % SCALAR_ORDER).to_bytes(32, "little")


def _wrapping_add_256(left: bytes, right: bytes) -> bytes:
    joined = (int.from_bytes(left, "little") + int.from_bytes(right, "little"))
    return (joined & SEED_MODULUS_MASK).to_bytes(32, "little")


def _derive_differential_wide(public_test_seed: bytes, case_index: int, field_tag: int) -> bytes:
    preimage = (
        DIFFERENTIAL_INPUT_DOMAIN_V1
        + b"\x00"
        + public_test_seed
        + case_index.to_bytes(4, "big")
        + field_tag.to_bytes(1, "big")
    )
    return hashlib.sha512(preimage).digest()


def _verify_differential_source(
    reference: Any,
    request_kind: str,
    case_index: int,
    public_test_seed: bytes,
    path: str,
) -> None:
    expected_kind = REQUEST_KIND_CYCLE[case_index % len(REQUEST_KIND_CYCLE)]
    if request_kind != expected_kind:
        raise VerificationError(
            f"{path} request kind must be {expected_kind!r} for differential index {case_index}"
        )

    reference_object = _require_exact_keys(reference, REFERENCE_KEYS, path)
    expected_case_id = f"differential_{case_index:04}_{expected_kind}_v1"
    case_id = _require_string(reference_object["case_id"], f"{path}.case_id")
    if case_id != expected_case_id:
        raise VerificationError(f"{path}.case_id must equal {expected_case_id!r}")

    inputs_path = f"{path}.inputs"
    inputs = _require_exact_keys(reference_object["inputs"], INPUT_KEYS, inputs_path)
    y_fields = (
        ("y_client_a_hex", 0x01),
        ("y_server_a_hex", 0x02),
        ("y_client_b_hex", 0x03),
        ("y_server_b_hex", 0x04),
    )
    tau_fields = (
        ("tau_client_a_hex", 0x05),
        ("tau_server_a_hex", 0x06),
        ("tau_client_b_hex", 0x07),
        ("tau_server_b_hex", 0x08),
    )
    for field_name, field_tag in y_fields:
        expected = _derive_differential_wide(
            public_test_seed, case_index, field_tag
        )[:32]
        _require_expected_bytes(inputs[field_name], expected, f"{inputs_path}.{field_name}")
    for field_name, field_tag in tau_fields:
        wide = _derive_differential_wide(public_test_seed, case_index, field_tag)
        scalar = int.from_bytes(wide, "little") % SCALAR_ORDER
        _require_expected_bytes(
            inputs[field_name], scalar.to_bytes(32, "little"), f"{inputs_path}.{field_name}"
        )

    context_path = f"{path}.context"
    context = _require_exact_keys(reference_object["context"], CONTEXT_KEYS, context_path)
    application_digest = _derive_differential_wide(
        public_test_seed, case_index, 0x09
    )[:32]
    _require_expected_bytes(
        context["application_binding_digest_hex"],
        application_digest,
        f"{context_path}.application_binding_digest_hex",
    )
    participant_low = (case_index % 32_767) + 1
    expected_participants = [participant_low, participant_low + 32_768]
    if context["participant_ids"] != expected_participants:
        raise VerificationError(
            f"{context_path}.participant_ids must equal {expected_participants}"
        )


def _verify_context(context: Any, path: str) -> bytes:
    context_object = _require_exact_keys(context, CONTEXT_KEYS, path)
    application_digest = _decode_hex(
        context_object["application_binding_digest_hex"],
        32,
        f"{path}.application_binding_digest_hex",
    )
    participant_ids = context_object["participant_ids"]
    if type(participant_ids) is not list or len(participant_ids) != 2:
        raise VerificationError(f"{path}.participant_ids must contain exactly two integers")
    for index, participant_id in enumerate(participant_ids):
        if type(participant_id) is not int or not 1 <= participant_id <= 0xFFFF:
            raise VerificationError(
                f"{path}.participant_ids[{index}] must be a nonzero u16"
            )
    if participant_ids[0] >= participant_ids[1]:
        raise VerificationError(
            f"{path}.participant_ids must be distinct and in ascending order"
        )

    encoded = (
        STABLE_CONTEXT_DOMAIN_V1
        + application_digest
        + participant_ids[0].to_bytes(2, "big")
        + participant_ids[1].to_bytes(2, "big")
    )
    _require_expected_bytes(context_object["encoded_hex"], encoded, f"{path}.encoded_hex")
    binding = hashlib.sha256(STABLE_CONTEXT_BINDING_DOMAIN_V1 + encoded).digest()
    _require_expected_bytes(
        context_object["binding_sha256_hex"],
        binding,
        f"{path}.binding_sha256_hex",
    )
    return binding


def _verify_reference(reference: Any, path: str, case_ids: set[str]) -> bytes:
    reference_object = _require_exact_keys(reference, REFERENCE_KEYS, path)
    case_id = _require_string(reference_object["case_id"], f"{path}.case_id")
    if not 1 <= len(case_id) <= 256 or any(
        ord(character) < 0x21 or ord(character) > 0x7E for character in case_id
    ):
        raise VerificationError(f"{path}.case_id must be 1-256 printable ASCII characters")
    if case_id in case_ids:
        raise VerificationError(f"{path}.case_id duplicates {case_id!r}")
    case_ids.add(case_id)

    _verify_context(reference_object["context"], f"{path}.context")
    inputs = _require_exact_keys(reference_object["inputs"], INPUT_KEYS, f"{path}.inputs")
    trace_path = f"{path}.clear_reference_trace"
    trace = _require_exact_keys(reference_object["clear_reference_trace"], TRACE_KEYS, trace_path)

    y_client_a = _decode_hex(inputs["y_client_a_hex"], 32, f"{path}.inputs.y_client_a_hex")
    y_server_a = _decode_hex(inputs["y_server_a_hex"], 32, f"{path}.inputs.y_server_a_hex")
    y_client_b = _decode_hex(inputs["y_client_b_hex"], 32, f"{path}.inputs.y_client_b_hex")
    y_server_b = _decode_hex(inputs["y_server_b_hex"], 32, f"{path}.inputs.y_server_b_hex")
    tau_client_a = _decode_scalar(
        inputs["tau_client_a_hex"], f"{path}.inputs.tau_client_a_hex"
    )
    tau_server_a = _decode_scalar(
        inputs["tau_server_a_hex"], f"{path}.inputs.tau_server_a_hex"
    )
    tau_client_b = _decode_scalar(
        inputs["tau_client_b_hex"], f"{path}.inputs.tau_client_b_hex"
    )
    tau_server_b = _decode_scalar(
        inputs["tau_server_b_hex"], f"{path}.inputs.tau_server_b_hex"
    )

    y_a = _wrapping_add_256(y_client_a, y_server_a)
    y_b = _wrapping_add_256(y_client_b, y_server_b)
    joined_seed = _wrapping_add_256(y_a, y_b)
    sha512_digest = hashlib.sha512(joined_seed).digest()
    clamped_scalar_bytes = bytearray(sha512_digest[:32])
    clamped_scalar_bytes[0] &= 248
    clamped_scalar_bytes[31] &= 63
    clamped_scalar_bytes[31] |= 64
    clamped_scalar_bytes = bytes(clamped_scalar_bytes)
    clamped_scalar = int.from_bytes(clamped_scalar_bytes, "little")
    signing_scalar = clamped_scalar % SCALAR_ORDER
    tau_a = (tau_client_a + tau_server_a) % SCALAR_ORDER
    tau_b = (tau_client_b + tau_server_b) % SCALAR_ORDER
    tau = (tau_a + tau_b) % SCALAR_ORDER
    x_client_base = (signing_scalar + tau) % SCALAR_ORDER
    x_server_base = (signing_scalar + 2 * tau) % SCALAR_ORDER

    _require_expected_bytes(trace["y_a_hex"], y_a, f"{trace_path}.y_a_hex")
    _require_expected_bytes(trace["y_b_hex"], y_b, f"{trace_path}.y_b_hex")
    _require_expected_bytes(
        trace["joined_seed_hex"], joined_seed, f"{trace_path}.joined_seed_hex"
    )
    _require_expected_bytes(
        trace["sha512_digest_hex"], sha512_digest, f"{trace_path}.sha512_digest_hex"
    )
    _require_expected_bytes(
        trace["clamped_scalar_bytes_hex"],
        clamped_scalar_bytes,
        f"{trace_path}.clamped_scalar_bytes_hex",
    )
    _require_expected_bytes(
        trace["signing_scalar_hex"],
        _encode_scalar(signing_scalar),
        f"{trace_path}.signing_scalar_hex",
    )
    _require_expected_bytes(trace["tau_a_hex"], _encode_scalar(tau_a), f"{trace_path}.tau_a_hex")
    _require_expected_bytes(trace["tau_b_hex"], _encode_scalar(tau_b), f"{trace_path}.tau_b_hex")
    _require_expected_bytes(trace["tau_hex"], _encode_scalar(tau), f"{trace_path}.tau_hex")
    _require_expected_bytes(
        trace["x_client_base_hex"],
        _encode_scalar(x_client_base),
        f"{trace_path}.x_client_base_hex",
    )
    _require_expected_bytes(
        trace["x_server_base_hex"],
        _encode_scalar(x_server_base),
        f"{trace_path}.x_server_base_hex",
    )

    x_client_point = _compress_point(_multiply_base(x_client_base))
    x_server_point = _compress_point(_multiply_base(x_server_base))
    public_key = _compress_point(_multiply_base(signing_scalar))
    public_key_from_clamped_scalar = _compress_point(_multiply_base(clamped_scalar))
    if public_key != public_key_from_clamped_scalar:
        raise VerificationError(f"{path} violates RFC 8032 scalar-reduction equivalence")

    _require_expected_bytes(
        trace["x_client_point_hex"], x_client_point, f"{trace_path}.x_client_point_hex"
    )
    _require_expected_bytes(
        trace["x_server_point_hex"], x_server_point, f"{trace_path}.x_server_point_hex"
    )
    _require_expected_bytes(trace["public_key_hex"], public_key, f"{trace_path}.public_key_hex")
    return joined_seed


def _hkdf_expand_sha256(pseudorandom_key: bytes, info: bytes, output_length: int) -> bytes:
    if output_length <= 0 or output_length > 255 * hashlib.sha256().digest_size:
        raise VerificationError("internal HKDF-SHA256 output length is invalid")
    block_count = (output_length + hashlib.sha256().digest_size - 1) // hashlib.sha256().digest_size
    output = bytearray()
    previous = b""
    for counter in range(1, block_count + 1):
        previous = hmac.new(
            pseudorandom_key,
            previous + info + counter.to_bytes(1, "big"),
            hashlib.sha256,
        ).digest()
        output.extend(previous)
    return bytes(output[:output_length])


def _derive_kdf_contribution(
    root: bytes, context_binding: bytes, role_tag: int, source_tag: int
) -> tuple[bytes, bytes]:
    pseudorandom_key = hmac.new(
        CONTRIBUTION_KDF_EXTRACT_SALT_V1, root, hashlib.sha256
    ).digest()
    info_prefix = CONTRIBUTION_KDF_EXPAND_INFO_DOMAIN_V1 + bytes(
        (0x00, role_tag, source_tag)
    )
    y = _hkdf_expand_sha256(pseudorandom_key, info_prefix + b"\x01" + context_binding, 32)
    tau_wide = _hkdf_expand_sha256(
        pseudorandom_key, info_prefix + b"\x02" + context_binding, 64
    )
    tau = (int.from_bytes(tau_wide, "little") % SCALAR_ORDER).to_bytes(32, "little")
    return y, tau


def verify_kdf_corpus(corpus: Any) -> int:
    """Independently verifies a strict contribution-KDF continuity corpus."""
    corpus_object = _require_exact_keys(corpus, {"schema", "protocol_id", "cases"}, "$")
    schema = _require_string(corpus_object["schema"], "$.schema")
    if schema != KDF_VECTOR_CORPUS_SCHEMA_V1:
        raise VerificationError(f"$.schema must equal {KDF_VECTOR_CORPUS_SCHEMA_V1!r}")
    protocol_id = _require_string(corpus_object["protocol_id"], "$.protocol_id")
    if protocol_id != PROTOCOL_ID_V1:
        raise VerificationError(f"$.protocol_id must equal {PROTOCOL_ID_V1!r}")
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) == 0:
        raise VerificationError("$.cases must be a nonempty JSON array")

    case_ids: set[str] = set()
    for index, case in enumerate(cases):
        case_path = f"$.cases[{index}]"
        case_object = _require_exact_keys(case, KDF_CASE_KEYS, case_path)
        application_binding_digest = _verify_application_binding(
            case_object["application_binding"], f"{case_path}.application_binding"
        )
        roots_path = f"{case_path}.synthetic_roots"
        roots = _require_exact_keys(
            case_object["synthetic_roots"], KDF_ROOT_KEYS, roots_path
        )
        client_root = _decode_hex(roots["client_root_hex"], 32, f"{roots_path}.client_root_hex")
        deriver_a_root = _decode_hex(
            roots["deriver_a_root_hex"], 32, f"{roots_path}.deriver_a_root_hex"
        )
        deriver_b_root = _decode_hex(
            roots["deriver_b_root_hex"], 32, f"{roots_path}.deriver_b_root_hex"
        )

        context_path = f"{case_path}.context"
        context_binding = _verify_context(case_object["context"], context_path)
        context_application_binding_digest = _decode_hex(
            case_object["context"]["application_binding_digest_hex"],
            32,
            f"{context_path}.application_binding_digest_hex",
        )
        if context_application_binding_digest != application_binding_digest:
            raise VerificationError(
                f"{context_path}.application_binding_digest_hex does not match "
                f"{case_path}.application_binding.digest_sha256_hex"
            )
        client_a_y, client_a_tau = _derive_kdf_contribution(
            client_root, context_binding, 0x01, 0x01
        )
        client_b_y, client_b_tau = _derive_kdf_contribution(
            client_root, context_binding, 0x02, 0x01
        )
        server_a_y, server_a_tau = _derive_kdf_contribution(
            deriver_a_root, context_binding, 0x01, 0x02
        )
        server_b_y, server_b_tau = _derive_kdf_contribution(
            deriver_b_root, context_binding, 0x02, 0x02
        )
        expected_contributions = {
            "y_client_a_hex": client_a_y,
            "tau_client_a_hex": client_a_tau,
            "y_client_b_hex": client_b_y,
            "tau_client_b_hex": client_b_tau,
            "y_server_a_hex": server_a_y,
            "tau_server_a_hex": server_a_tau,
            "y_server_b_hex": server_b_y,
            "tau_server_b_hex": server_b_tau,
        }
        contributions_path = f"{case_path}.contributions"
        contributions = _require_exact_keys(
            case_object["contributions"], INPUT_KEYS, contributions_path
        )
        for field_name, expected in expected_contributions.items():
            _require_expected_bytes(
                contributions[field_name], expected, f"{contributions_path}.{field_name}"
            )

        reference = {
            "case_id": case_object["case_id"],
            "context": case_object["context"],
            "inputs": contributions,
            "clear_reference_trace": case_object["synthetic_clear_reference_trace"],
        }
        _verify_reference(reference, case_path, case_ids)

    return len(cases)


def _require_exact_value(value: Any, expected: Any, path: str) -> None:
    if value != expected:
        raise VerificationError(f"{path} must equal {expected!r}")


def _require_epoch(value: Any, path: str) -> int:
    if type(value) is not int or not 1 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise VerificationError(f"{path} must be a nonzero u64")
    return value


def _require_u8(value: Any, path: str) -> int:
    if type(value) is not int or not 0 <= value <= 0xFF:
        raise VerificationError(f"{path} must be a u8")
    return value


def _verify_lifecycle_case_id(value: Any, expected: str, path: str) -> str:
    case_id = _require_string(value, path)
    if not case_id or any(ord(character) < 0x21 or ord(character) > 0x7E for character in case_id):
        raise VerificationError(f"{path} must be nonempty visible ASCII")
    _require_exact_value(case_id, expected, path)
    return case_id


def _scan_lifecycle_public_boundary(value: Any, path: str) -> None:
    if type(value) is dict:
        for key, nested in value.items():
            if any(key.endswith(suffix) for suffix in LIFECYCLE_PUBLIC_FORBIDDEN_SUFFIXES_V1):
                raise VerificationError(f"{path}.{key} is forbidden in a public lifecycle object")
            _scan_lifecycle_public_boundary(nested, f"{path}.{key}")
    elif type(value) is list:
        for index, nested in enumerate(value):
            _scan_lifecycle_public_boundary(nested, f"{path}[{index}]")


def _verify_lifecycle_identity(identity: Any, path: str) -> dict[str, Any]:
    identity_object = _require_ordered_keys(identity, LIFECYCLE_IDENTITY_KEY_ORDER, path)
    _scan_lifecycle_public_boundary(identity_object, path)

    binding_path = f"{path}.application_binding"
    binding = _require_ordered_keys(
        identity_object["application_binding"],
        LIFECYCLE_APPLICATION_BINDING_KEY_ORDER,
        binding_path,
    )
    application_binding_digest = _verify_application_binding(binding, binding_path)
    _require_exact_value(binding["wallet_id"], LIFECYCLE_WALLET_ID_V1, f"{binding_path}.wallet_id")
    _require_exact_value(
        binding["near_ed25519_signing_key_id"],
        LIFECYCLE_SIGNING_KEY_ID_V1,
        f"{binding_path}.near_ed25519_signing_key_id",
    )
    _require_exact_value(
        binding["signing_root_id"],
        LIFECYCLE_SIGNING_ROOT_ID_V1,
        f"{binding_path}.signing_root_id",
    )
    _require_exact_value(
        binding["key_creation_signer_slot"],
        LIFECYCLE_KEY_CREATION_SIGNER_SLOT_V1,
        f"{binding_path}.key_creation_signer_slot",
    )

    context_path = f"{path}.context"
    context = _require_ordered_keys(
        identity_object["context"], LIFECYCLE_CONTEXT_KEY_ORDER, context_path
    )
    context_binding = _verify_context(context, context_path)
    context_application_binding_digest = _decode_hex(
        context["application_binding_digest_hex"],
        32,
        f"{context_path}.application_binding_digest_hex",
    )
    if context_application_binding_digest != application_binding_digest:
        raise VerificationError(
            f"{context_path}.application_binding_digest_hex does not match "
            f"{binding_path}.digest_sha256_hex"
        )
    _require_exact_value(context["participant_ids"], [1, 2], f"{context_path}.participant_ids")

    registered_public_key = _decode_hex(
        identity_object["registered_public_key_hex"],
        32,
        f"{path}.registered_public_key_hex",
    )
    x_client_point = _decode_hex(
        identity_object["x_client_point_hex"], 32, f"{path}.x_client_point_hex"
    )
    x_server_point = _decode_hex(
        identity_object["x_server_point_hex"], 32, f"{path}.x_server_point_hex"
    )
    if registered_public_key != LIFECYCLE_PUBLIC_KEY_V1:
        raise VerificationError(f"{path}.registered_public_key_hex is not the canonical fixture key")
    if x_client_point != LIFECYCLE_X_CLIENT_POINT_V1:
        raise VerificationError(f"{path}.x_client_point_hex is not the canonical fixture point")
    if x_server_point != LIFECYCLE_X_SERVER_POINT_V1:
        raise VerificationError(f"{path}.x_server_point_hex is not the canonical fixture point")

    return {
        "object": identity_object,
        "context": context,
        "context_binding": context_binding,
        "registered_public_key": registered_public_key,
        "x_client_point": x_client_point,
        "x_server_point": x_server_point,
    }


def _verify_lifecycle_role_epoch(value: Any, path: str) -> tuple[int, int]:
    role_epoch = _require_ordered_keys(value, LIFECYCLE_ROLE_EPOCH_KEY_ORDER, path)
    return (
        _require_epoch(role_epoch["role_root_epoch"], f"{path}.role_root_epoch"),
        _require_epoch(
            role_epoch["role_input_state_epoch"], f"{path}.role_input_state_epoch"
        ),
    )


def _verify_lifecycle_role_epoch_pair(
    value: Any, path: str
) -> tuple[tuple[int, int], tuple[int, int]]:
    pair = _require_ordered_keys(value, LIFECYCLE_ROLE_EPOCH_PAIR_KEY_ORDER, path)
    return (
        _verify_lifecycle_role_epoch(pair["deriver_a"], f"{path}.deriver_a"),
        _verify_lifecycle_role_epoch(pair["deriver_b"], f"{path}.deriver_b"),
    )


def _verify_lifecycle_active_state(value: Any, path: str) -> dict[str, Any]:
    state = _require_ordered_keys(value, LIFECYCLE_ACTIVE_STATE_KEY_ORDER, path)
    _scan_lifecycle_public_boundary(state, path)
    return {
        "object": state,
        "identity": _verify_lifecycle_identity(state["identity"], f"{path}.identity"),
        "epochs": _verify_lifecycle_role_epoch_pair(
            state["active_role_epochs"], f"{path}.active_role_epochs"
        ),
        "activation_epoch": _require_epoch(
            state["active_activation_epoch"], f"{path}.active_activation_epoch"
        ),
    }


def _verify_lifecycle_registration_pending_state(
    value: Any, path: str
) -> dict[str, Any]:
    state = _require_ordered_keys(
        value, LIFECYCLE_REGISTRATION_PENDING_STATE_KEY_ORDER, path
    )
    _scan_lifecycle_public_boundary(state, path)
    return {
        "object": state,
        "identity": _verify_lifecycle_identity(state["identity"], f"{path}.identity"),
        "candidate_epochs": _verify_lifecycle_role_epoch_pair(
            state["candidate_role_epochs"], f"{path}.candidate_role_epochs"
        ),
        "pending_activation_epoch": _require_epoch(
            state["pending_activation_epoch"], f"{path}.pending_activation_epoch"
        ),
    }


def _verify_lifecycle_recovery_pending_state(value: Any, path: str) -> dict[str, Any]:
    state = _require_ordered_keys(
        value, LIFECYCLE_RECOVERY_PENDING_STATE_KEY_ORDER, path
    )
    _scan_lifecycle_public_boundary(state, path)
    return {
        "object": state,
        "identity": _verify_lifecycle_identity(state["identity"], f"{path}.identity"),
        "current_epochs": _verify_lifecycle_role_epoch_pair(
            state["current_role_epochs"], f"{path}.current_role_epochs"
        ),
        "active_activation_epoch": _require_epoch(
            state["active_activation_epoch"], f"{path}.active_activation_epoch"
        ),
        "pending_activation_epoch": _require_epoch(
            state["pending_activation_epoch"], f"{path}.pending_activation_epoch"
        ),
    }


def _verify_lifecycle_refresh_pending_state(value: Any, path: str) -> dict[str, Any]:
    state = _require_ordered_keys(
        value, LIFECYCLE_REFRESH_PENDING_STATE_KEY_ORDER, path
    )
    _scan_lifecycle_public_boundary(state, path)
    _require_exact_value(state["derivation_admission"], "frozen", f"{path}.derivation_admission")
    return {
        "object": state,
        "identity": _verify_lifecycle_identity(state["identity"], f"{path}.identity"),
        "current_epochs": _verify_lifecycle_role_epoch_pair(
            state["current_role_epochs"], f"{path}.current_role_epochs"
        ),
        "next_epochs": _verify_lifecycle_role_epoch_pair(
            state["next_role_epochs"], f"{path}.next_role_epochs"
        ),
        "active_activation_epoch": _require_epoch(
            state["active_activation_epoch"], f"{path}.active_activation_epoch"
        ),
        "pending_activation_epoch": _require_epoch(
            state["pending_activation_epoch"], f"{path}.pending_activation_epoch"
        ),
    }


def _verify_lifecycle_refresh_activated_state(value: Any, path: str) -> dict[str, Any]:
    state = _require_ordered_keys(
        value, LIFECYCLE_REFRESH_ACTIVATED_STATE_KEY_ORDER, path
    )
    _scan_lifecycle_public_boundary(state, path)
    retired_path = f"{path}.retired_role_input_state_epochs"
    retired = _require_ordered_keys(
        state["retired_role_input_state_epochs"],
        LIFECYCLE_RETIRED_EPOCH_KEY_ORDER,
        retired_path,
    )
    retired_epochs = (
        _require_epoch(retired["deriver_a"], f"{retired_path}.deriver_a"),
        _require_epoch(retired["deriver_b"], f"{retired_path}.deriver_b"),
    )
    _require_exact_value(state["derivation_admission"], "open", f"{path}.derivation_admission")
    return {
        "object": state,
        "identity": _verify_lifecycle_identity(state["identity"], f"{path}.identity"),
        "active_epochs": _verify_lifecycle_role_epoch_pair(
            state["active_role_epochs"], f"{path}.active_role_epochs"
        ),
        "retired_epochs": retired_epochs,
        "activation_epoch": _require_epoch(
            state["active_activation_epoch"], f"{path}.active_activation_epoch"
        ),
    }


def _verify_lifecycle_counts(value: Any, expected: dict[str, int], path: str) -> None:
    counts = _require_ordered_keys(value, LIFECYCLE_OPERATION_COUNT_KEY_ORDER, path)
    _scan_lifecycle_public_boundary(counts, path)
    for field_name in LIFECYCLE_OPERATION_COUNT_KEY_ORDER:
        actual = _require_u8(counts[field_name], f"{path}.{field_name}")
        if actual != expected[field_name]:
            raise VerificationError(
                f"{path}.{field_name} must equal {expected[field_name]} for this lifecycle case"
            )


def _verify_lifecycle_roots(value: Any, path: str) -> dict[str, bytes]:
    roots = _require_ordered_keys(value, LIFECYCLE_ROOT_KEY_ORDER, path)
    decoded = {
        field_name: _decode_hex(roots[field_name], 32, f"{path}.{field_name}")
        for field_name in LIFECYCLE_ROOT_KEY_ORDER
    }
    expected = {
        "client_root_hex": LIFECYCLE_CLIENT_ROOT_V1,
        "deriver_a_root_hex": LIFECYCLE_DERIVER_A_ROOT_V1,
        "deriver_b_root_hex": LIFECYCLE_DERIVER_B_ROOT_V1,
    }
    for field_name, expected_bytes in expected.items():
        if decoded[field_name] != expected_bytes:
            raise VerificationError(f"{path}.{field_name} is not the canonical synthetic root")
    return decoded


def _verify_lifecycle_contributions(value: Any, path: str) -> dict[str, bytes]:
    contributions = _require_ordered_keys(
        value, LIFECYCLE_CONTRIBUTION_KEY_ORDER, path
    )
    decoded: dict[str, bytes] = {}
    for field_name in LIFECYCLE_CONTRIBUTION_KEY_ORDER:
        if field_name.startswith("tau_"):
            scalar = _decode_scalar(contributions[field_name], f"{path}.{field_name}")
            decoded[field_name] = scalar.to_bytes(32, "little")
        else:
            decoded[field_name] = _decode_hex(
                contributions[field_name], 32, f"{path}.{field_name}"
            )
    return decoded


def _verify_lifecycle_client_contributions(value: Any, path: str) -> dict[str, bytes]:
    contributions = _require_ordered_keys(
        value, LIFECYCLE_CLIENT_CONTRIBUTION_KEY_ORDER, path
    )
    decoded: dict[str, bytes] = {}
    for field_name in LIFECYCLE_CLIENT_CONTRIBUTION_KEY_ORDER:
        if field_name.startswith("tau_"):
            scalar = _decode_scalar(contributions[field_name], f"{path}.{field_name}")
            decoded[field_name] = scalar.to_bytes(32, "little")
        else:
            decoded[field_name] = _decode_hex(
                contributions[field_name], 32, f"{path}.{field_name}"
            )
    return decoded


def _derive_lifecycle_contributions(
    roots: dict[str, bytes], context_binding: bytes
) -> dict[str, bytes]:
    client_a_y, client_a_tau = _derive_kdf_contribution(
        roots["client_root_hex"], context_binding, 0x01, 0x01
    )
    client_b_y, client_b_tau = _derive_kdf_contribution(
        roots["client_root_hex"], context_binding, 0x02, 0x01
    )
    server_a_y, server_a_tau = _derive_kdf_contribution(
        roots["deriver_a_root_hex"], context_binding, 0x01, 0x02
    )
    server_b_y, server_b_tau = _derive_kdf_contribution(
        roots["deriver_b_root_hex"], context_binding, 0x02, 0x02
    )
    return {
        "y_client_a_hex": client_a_y,
        "tau_client_a_hex": client_a_tau,
        "y_client_b_hex": client_b_y,
        "tau_client_b_hex": client_b_tau,
        "y_server_a_hex": server_a_y,
        "tau_server_a_hex": server_a_tau,
        "y_server_b_hex": server_b_y,
        "tau_server_b_hex": server_b_tau,
    }


def _require_lifecycle_contributions_equal(
    actual: dict[str, bytes], expected: dict[str, bytes], path: str
) -> None:
    for field_name in expected:
        if actual[field_name] != expected[field_name]:
            raise VerificationError(
                f"{path}.{field_name} does not match the independently computed value"
            )


def _verify_lifecycle_trace(
    context: dict[str, Any],
    contributions: Any,
    trace: Any,
    path: str,
) -> dict[str, Any]:
    contribution_object = _require_ordered_keys(
        contributions, LIFECYCLE_CONTRIBUTION_KEY_ORDER, f"{path}.inputs"
    )
    trace_object = _require_ordered_keys(
        trace, LIFECYCLE_TRACE_KEY_ORDER, f"{path}.clear_reference_trace"
    )
    reference = {
        "case_id": "lifecycle_trace_reference_v1",
        "context": context,
        "inputs": contribution_object,
        "clear_reference_trace": trace_object,
    }
    _verify_reference(reference, path, set())
    return trace_object


def _require_lifecycle_identity_matches_trace(
    identity: dict[str, Any], trace: dict[str, Any], path: str
) -> None:
    expected = (
        ("registered_public_key", "public_key_hex"),
        ("x_client_point", "x_client_point_hex"),
        ("x_server_point", "x_server_point_hex"),
    )
    for identity_field, trace_field in expected:
        trace_value = _decode_hex(trace[trace_field], 32, f"{path}.{trace_field}")
        if identity[identity_field] != trace_value:
            raise VerificationError(
                f"{path}.{trace_field} does not match the public fixture identity"
            )


def _recovery_counts_v1() -> dict[str, int]:
    return {
        "deriver_a_invocations": 1,
        "deriver_b_invocations": 1,
        "client_kdf_derivations_a": 1,
        "client_kdf_derivations_b": 1,
        "server_kdf_derivations_a": 0,
        "server_kdf_derivations_b": 0,
        "activation_family_evaluations": 1,
        "export_family_evaluations": 0,
        "pending_activation_consumptions": 0,
    }


def _registration_metadata_counts_v1() -> dict[str, int]:
    return {
        "deriver_a_invocations": 0,
        "deriver_b_invocations": 0,
        "client_kdf_derivations_a": 0,
        "client_kdf_derivations_b": 0,
        "server_kdf_derivations_a": 0,
        "server_kdf_derivations_b": 0,
        "activation_family_evaluations": 0,
        "export_family_evaluations": 0,
        "pending_activation_consumptions": 0,
    }


def _refresh_counts_v1() -> dict[str, int]:
    return {
        "deriver_a_invocations": 1,
        "deriver_b_invocations": 1,
        "client_kdf_derivations_a": 0,
        "client_kdf_derivations_b": 0,
        "server_kdf_derivations_a": 0,
        "server_kdf_derivations_b": 0,
        "activation_family_evaluations": 1,
        "export_family_evaluations": 0,
        "pending_activation_consumptions": 0,
    }


def _activation_counts_v1() -> dict[str, int]:
    return {
        "deriver_a_invocations": 0,
        "deriver_b_invocations": 0,
        "client_kdf_derivations_a": 0,
        "client_kdf_derivations_b": 0,
        "server_kdf_derivations_a": 0,
        "server_kdf_derivations_b": 0,
        "activation_family_evaluations": 0,
        "export_family_evaluations": 0,
        "pending_activation_consumptions": 1,
    }


def _verify_registration_lifecycle_case(vector: Any, path: str) -> dict[str, Any]:
    registration = _require_ordered_keys(
        vector, LIFECYCLE_REGISTRATION_VECTOR_KEY_ORDER, path
    )
    pending = _verify_lifecycle_registration_pending_state(
        registration["pending_public"], f"{path}.pending_public"
    )
    _require_exact_value(
        pending["candidate_epochs"],
        ((3, 11), (9, 41)),
        f"{path}.pending_public.candidate_role_epochs",
    )
    _require_exact_value(
        pending["pending_activation_epoch"],
        7,
        f"{path}.pending_public.pending_activation_epoch",
    )
    _verify_lifecycle_counts(
        registration["reference_operation_counts"],
        _registration_metadata_counts_v1(),
        f"{path}.reference_operation_counts",
    )
    return {"kind": "registration", "pending": pending["object"]}


def _verify_recovery_lifecycle_case(vector: Any, path: str) -> dict[str, Any]:
    recovery = _require_ordered_keys(vector, LIFECYCLE_RECOVERY_VECTOR_KEY_ORDER, path)
    before = _verify_lifecycle_active_state(recovery["before_public"], f"{path}.before_public")
    pending = _verify_lifecycle_recovery_pending_state(
        recovery["pending_public"], f"{path}.pending_public"
    )
    expected_epochs = ((3, 11), (9, 41))
    _require_exact_value(before["epochs"], expected_epochs, f"{path}.before_public.active_role_epochs")
    _require_exact_value(before["activation_epoch"], 7, f"{path}.before_public.active_activation_epoch")
    if pending["identity"]["object"] != before["identity"]["object"]:
        raise VerificationError(f"{path}.pending_public.identity must equal before_public.identity")
    _require_exact_value(
        pending["current_epochs"], expected_epochs, f"{path}.pending_public.current_role_epochs"
    )
    _require_exact_value(
        pending["active_activation_epoch"], 7, f"{path}.pending_public.active_activation_epoch"
    )
    _require_exact_value(
        pending["pending_activation_epoch"], 8, f"{path}.pending_public.pending_activation_epoch"
    )
    if pending["pending_activation_epoch"] <= pending["active_activation_epoch"]:
        raise VerificationError(f"{path}.pending_public pending activation epoch must advance")
    _verify_lifecycle_counts(
        recovery["reference_operation_counts"],
        _recovery_counts_v1(),
        f"{path}.reference_operation_counts",
    )

    host_path = f"{path}.host_only_reference"
    host = _require_ordered_keys(
        recovery["host_only_reference"], LIFECYCLE_RECOVERY_HOST_KEY_ORDER, host_path
    )
    roots = _verify_lifecycle_roots(host["synthetic_roots"], f"{host_path}.synthetic_roots")
    expected_contributions = _derive_lifecycle_contributions(
        roots, before["identity"]["context_binding"]
    )
    current = _verify_lifecycle_contributions(
        host["current_contributions"], f"{host_path}.current_contributions"
    )
    _require_lifecycle_contributions_equal(
        current, expected_contributions, f"{host_path}.current_contributions"
    )
    recovered_root = _decode_hex(
        host["recovered_client_root_hex"], 32, f"{host_path}.recovered_client_root_hex"
    )
    if recovered_root != roots["client_root_hex"]:
        raise VerificationError(
            f"{host_path}.recovered_client_root_hex must equal the current client root"
        )
    rederived_expected = _derive_lifecycle_contributions(
        {**roots, "client_root_hex": recovered_root},
        before["identity"]["context_binding"],
    )
    rederived = _verify_lifecycle_client_contributions(
        host["rederived_client_contributions"],
        f"{host_path}.rederived_client_contributions",
    )
    _require_lifecycle_contributions_equal(
        rederived,
        {field_name: rederived_expected[field_name] for field_name in LIFECYCLE_CLIENT_CONTRIBUTION_KEY_ORDER},
        f"{host_path}.rederived_client_contributions",
    )
    after = _verify_lifecycle_contributions(
        host["after_contributions"], f"{host_path}.after_contributions"
    )
    _require_lifecycle_contributions_equal(after, current, f"{host_path}.after_contributions")
    before_trace = _verify_lifecycle_trace(
        before["identity"]["context"],
        host["current_contributions"],
        host["before_clear_reference_trace"],
        f"{host_path}.before",
    )
    after_trace = _verify_lifecycle_trace(
        before["identity"]["context"],
        host["after_contributions"],
        host["after_clear_reference_trace"],
        f"{host_path}.after",
    )
    if after_trace != before_trace:
        raise VerificationError(
            f"{host_path}.after_clear_reference_trace must equal the before trace"
        )
    _require_lifecycle_identity_matches_trace(before["identity"], before_trace, host_path)
    return {"kind": "recovery", "pending": pending["object"]}


def _wrapping_sub_256(left: bytes, right: bytes) -> bytes:
    difference = int.from_bytes(left, "little") - int.from_bytes(right, "little")
    return (difference & SEED_MODULUS_MASK).to_bytes(32, "little")


def _verify_refresh_lifecycle_case(vector: Any, path: str) -> dict[str, Any]:
    refresh = _require_ordered_keys(vector, LIFECYCLE_REFRESH_VECTOR_KEY_ORDER, path)
    before = _verify_lifecycle_active_state(refresh["before_public"], f"{path}.before_public")
    pending = _verify_lifecycle_refresh_pending_state(
        refresh["pending_public"], f"{path}.pending_public"
    )
    current_epochs = ((3, 11), (9, 41))
    next_epochs = ((3, 12), (9, 43))
    _require_exact_value(before["epochs"], current_epochs, f"{path}.before_public.active_role_epochs")
    _require_exact_value(before["activation_epoch"], 8, f"{path}.before_public.active_activation_epoch")
    if pending["identity"]["object"] != before["identity"]["object"]:
        raise VerificationError(f"{path}.pending_public.identity must equal before_public.identity")
    _require_exact_value(
        pending["current_epochs"], current_epochs, f"{path}.pending_public.current_role_epochs"
    )
    _require_exact_value(pending["next_epochs"], next_epochs, f"{path}.pending_public.next_role_epochs")
    for role_index, role_name in enumerate(("deriver_a", "deriver_b")):
        current_root, current_input = pending["current_epochs"][role_index]
        next_root, next_input = pending["next_epochs"][role_index]
        if next_root != current_root:
            raise VerificationError(f"{path}.pending_public.{role_name} role-root epoch must stay fixed")
        if next_input <= current_input:
            raise VerificationError(f"{path}.pending_public.{role_name} input-state epoch must advance")
    _require_exact_value(
        pending["active_activation_epoch"], 8, f"{path}.pending_public.active_activation_epoch"
    )
    _require_exact_value(
        pending["pending_activation_epoch"], 9, f"{path}.pending_public.pending_activation_epoch"
    )
    if pending["pending_activation_epoch"] <= pending["active_activation_epoch"]:
        raise VerificationError(f"{path}.pending_public pending activation epoch must advance")
    _verify_lifecycle_counts(
        refresh["reference_operation_counts"],
        _refresh_counts_v1(),
        f"{path}.reference_operation_counts",
    )

    host_path = f"{path}.host_only_reference"
    host = _require_ordered_keys(
        refresh["host_only_reference"], LIFECYCLE_REFRESH_HOST_KEY_ORDER, host_path
    )
    roots = _verify_lifecycle_roots(host["synthetic_roots"], f"{host_path}.synthetic_roots")
    expected_before = _derive_lifecycle_contributions(
        roots, before["identity"]["context_binding"]
    )
    before_contributions = _verify_lifecycle_contributions(
        host["before_contributions"], f"{host_path}.before_contributions"
    )
    _require_lifecycle_contributions_equal(
        before_contributions, expected_before, f"{host_path}.before_contributions"
    )
    delta_path = f"{host_path}.delta"
    delta = _require_ordered_keys(host["delta"], LIFECYCLE_REFRESH_DELTA_KEY_ORDER, delta_path)
    a_path = f"{delta_path}.deriver_a"
    a = _require_ordered_keys(
        delta["deriver_a"], LIFECYCLE_REFRESH_DELTA_CONTRIBUTION_KEY_ORDER, a_path
    )
    b_path = f"{delta_path}.deriver_b"
    b = _require_ordered_keys(
        delta["deriver_b"], LIFECYCLE_REFRESH_DELTA_CONTRIBUTION_KEY_ORDER, b_path
    )
    a_y = _decode_hex(a["delta_y_hex"], 32, f"{a_path}.delta_y_hex")
    a_tau = _decode_scalar(a["delta_tau_hex"], f"{a_path}.delta_tau_hex")
    b_y = _decode_hex(b["delta_y_hex"], 32, f"{b_path}.delta_y_hex")
    b_tau = _decode_scalar(b["delta_tau_hex"], f"{b_path}.delta_tau_hex")
    delta_y = _decode_hex(
        delta["combined_delta_y_hex"], 32, f"{delta_path}.combined_delta_y_hex"
    )
    delta_tau = _decode_scalar(
        delta["combined_delta_tau_hex"], f"{delta_path}.combined_delta_tau_hex"
    )
    if delta_y != _wrapping_add_256(a_y, b_y):
        raise VerificationError(f"{delta_path}.combined_delta_y_hex is not the role sum")
    if delta_tau != (a_tau + b_tau) % SCALAR_ORDER:
        raise VerificationError(f"{delta_path}.combined_delta_tau_hex is not the role sum")
    if delta_y == bytes(32):
        raise VerificationError(f"{delta_path}.combined_delta_y_hex must be nonzero")
    if delta_tau == 0:
        raise VerificationError(f"{delta_path}.combined_delta_tau_hex must be nonzero")
    if delta_y != LIFECYCLE_DELTA_Y_V1:
        raise VerificationError(
            f"{delta_path}.combined_delta_y_hex is not the canonical fixture delta"
        )
    if delta_tau != LIFECYCLE_DELTA_TAU_V1:
        raise VerificationError(
            f"{delta_path}.combined_delta_tau_hex is not the canonical fixture delta"
        )

    expected_after = dict(before_contributions)
    expected_after["y_server_a_hex"] = _wrapping_add_256(
        before_contributions["y_server_a_hex"], delta_y
    )
    expected_after["y_server_b_hex"] = _wrapping_sub_256(
        before_contributions["y_server_b_hex"], delta_y
    )
    expected_after["tau_server_a_hex"] = _encode_scalar(
        int.from_bytes(before_contributions["tau_server_a_hex"], "little") + delta_tau
    )
    expected_after["tau_server_b_hex"] = _encode_scalar(
        int.from_bytes(before_contributions["tau_server_b_hex"], "little") - delta_tau
    )
    after_contributions = _verify_lifecycle_contributions(
        host["after_contributions"], f"{host_path}.after_contributions"
    )
    _require_lifecycle_contributions_equal(
        after_contributions, expected_after, f"{host_path}.after_contributions"
    )
    before_trace = _verify_lifecycle_trace(
        before["identity"]["context"],
        host["before_contributions"],
        host["before_clear_reference_trace"],
        f"{host_path}.before",
    )
    after_trace = _verify_lifecycle_trace(
        before["identity"]["context"],
        host["after_contributions"],
        host["after_clear_reference_trace"],
        f"{host_path}.after",
    )
    role_local_trace_relations = (
        (
            "y_a_hex",
            _wrapping_add_256(bytes.fromhex(before_trace["y_a_hex"]), delta_y),
        ),
        (
            "y_b_hex",
            _wrapping_sub_256(bytes.fromhex(before_trace["y_b_hex"]), delta_y),
        ),
        (
            "tau_a_hex",
            _encode_scalar(
                int.from_bytes(bytes.fromhex(before_trace["tau_a_hex"]), "little")
                + delta_tau
            ),
        ),
        (
            "tau_b_hex",
            _encode_scalar(
                int.from_bytes(bytes.fromhex(before_trace["tau_b_hex"]), "little")
                - delta_tau
            ),
        ),
    )
    for field_name, expected_bytes in role_local_trace_relations:
        _require_expected_bytes(
            after_trace[field_name],
            expected_bytes,
            f"{host_path}.after_clear_reference_trace.{field_name}",
        )
    preserved_trace_fields = (
        "joined_seed_hex",
        "sha512_digest_hex",
        "clamped_scalar_bytes_hex",
        "signing_scalar_hex",
        "tau_hex",
        "x_client_base_hex",
        "x_server_base_hex",
        "x_client_point_hex",
        "x_server_point_hex",
        "public_key_hex",
    )
    for field_name in preserved_trace_fields:
        if after_trace[field_name] != before_trace[field_name]:
            raise VerificationError(
                f"{host_path}.after_clear_reference_trace.{field_name} must preserve identity"
            )
    _require_lifecycle_identity_matches_trace(before["identity"], before_trace, host_path)
    return {"kind": "refresh", "pending": pending["object"]}


def _verify_activation_lifecycle_case(
    vector: Any,
    expected_origin_kind: str,
    prior_cases: dict[str, dict[str, Any]],
    path: str,
) -> None:
    activation = _require_ordered_keys(
        vector, LIFECYCLE_ACTIVATION_VECTOR_KEY_ORDER, path
    )
    origin_kind = _require_string(activation["origin_kind"], f"{path}.origin_kind")
    if origin_kind not in LIFECYCLE_ORIGIN_CASE_ID_BY_KIND_V1:
        raise VerificationError(f"{path}.origin_kind is unsupported")
    _require_exact_value(origin_kind, expected_origin_kind, f"{path}.origin_kind")
    transition_path = f"{path}.transition"
    transition = _require_ordered_keys(
        activation["transition"], LIFECYCLE_ACTIVATION_TRANSITION_KEY_ORDER, transition_path
    )
    origin_case_id = _require_string(
        transition["origin_case_id"], f"{transition_path}.origin_case_id"
    )
    expected_origin_case_id = LIFECYCLE_ORIGIN_CASE_ID_BY_KIND_V1[origin_kind]
    _require_exact_value(
        origin_case_id, expected_origin_case_id, f"{transition_path}.origin_case_id"
    )
    origin = prior_cases.get(origin_case_id)
    if origin is None:
        raise VerificationError(
            f"{transition_path}.origin_case_id must reference an earlier lifecycle case"
        )
    if origin["kind"] != origin_kind:
        raise VerificationError(
            f"{transition_path}.origin_case_id has the wrong lifecycle request kind"
        )
    if transition["pending_public"] != origin["pending"]:
        raise VerificationError(
            f"{transition_path}.pending_public must equal the origin pending state byte-for-byte"
        )
    _verify_lifecycle_counts(
        transition["reference_operation_counts"],
        _activation_counts_v1(),
        f"{transition_path}.reference_operation_counts",
    )

    if origin_kind == "registration":
        pending = _verify_lifecycle_registration_pending_state(
            transition["pending_public"], f"{transition_path}.pending_public"
        )
        activated = _verify_lifecycle_active_state(
            transition["activated_public"], f"{transition_path}.activated_public"
        )
        if activated["identity"]["object"] != pending["identity"]["object"]:
            raise VerificationError(f"{transition_path}.activated_public.identity changed")
        _require_exact_value(
            activated["epochs"],
            pending["candidate_epochs"],
            f"{transition_path}.activated_public.active_role_epochs",
        )
        _require_exact_value(
            activated["activation_epoch"],
            pending["pending_activation_epoch"],
            f"{transition_path}.activated_public.active_activation_epoch",
        )
    elif origin_kind == "recovery":
        pending = _verify_lifecycle_recovery_pending_state(
            transition["pending_public"], f"{transition_path}.pending_public"
        )
        activated = _verify_lifecycle_active_state(
            transition["activated_public"], f"{transition_path}.activated_public"
        )
        if activated["identity"]["object"] != pending["identity"]["object"]:
            raise VerificationError(f"{transition_path}.activated_public.identity changed")
        _require_exact_value(
            activated["epochs"],
            pending["current_epochs"],
            f"{transition_path}.activated_public.active_role_epochs",
        )
        _require_exact_value(
            activated["activation_epoch"],
            pending["pending_activation_epoch"],
            f"{transition_path}.activated_public.active_activation_epoch",
        )
    else:
        pending = _verify_lifecycle_refresh_pending_state(
            transition["pending_public"], f"{transition_path}.pending_public"
        )
        activated = _verify_lifecycle_refresh_activated_state(
            transition["activated_public"], f"{transition_path}.activated_public"
        )
        if activated["identity"]["object"] != pending["identity"]["object"]:
            raise VerificationError(f"{transition_path}.activated_public.identity changed")
        _require_exact_value(
            activated["active_epochs"],
            pending["next_epochs"],
            f"{transition_path}.activated_public.active_role_epochs",
        )
        expected_retired = (
            pending["current_epochs"][0][1],
            pending["current_epochs"][1][1],
        )
        _require_exact_value(
            activated["retired_epochs"],
            expected_retired,
            f"{transition_path}.activated_public.retired_role_input_state_epochs",
        )
        _require_exact_value(
            activated["activation_epoch"],
            pending["pending_activation_epoch"],
            f"{transition_path}.activated_public.active_activation_epoch",
        )


def verify_lifecycle_continuity_corpus(corpus: Any) -> int:
    """Independently verifies the strict six-case host lifecycle corpus."""
    corpus_object = _require_ordered_keys(corpus, LIFECYCLE_CORPUS_KEY_ORDER, "$")
    _require_exact_value(
        _require_string(corpus_object["schema"], "$.schema"),
        LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(corpus_object["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(corpus_object["evidence_scope"], "$.evidence_scope"),
        LIFECYCLE_CONTINUITY_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) != len(LIFECYCLE_CASE_SEQUENCE_V1):
        raise VerificationError("$.cases must contain exactly six lifecycle cases")

    case_ids: set[str] = set()
    prior_cases: dict[str, dict[str, Any]] = {}
    for index, ((expected_kind, expected_case_id), case) in enumerate(
        zip(LIFECYCLE_CASE_SEQUENCE_V1, cases)
    ):
        case_path = f"$.cases[{index}]"
        case_object = _require_ordered_keys(case, LIFECYCLE_CASE_KEY_ORDER, case_path)
        request_kind = _require_string(
            case_object["request_kind"], f"{case_path}.request_kind"
        )
        if request_kind not in {"registration", "recovery", "activation", "refresh"}:
            raise VerificationError(f"{case_path}.request_kind is unsupported")
        _require_exact_value(request_kind, expected_kind, f"{case_path}.request_kind")

        vector_path = f"{case_path}.vector"
        if request_kind == "registration":
            vector = _require_ordered_keys(
                case_object["vector"], LIFECYCLE_REGISTRATION_VECTOR_KEY_ORDER, vector_path
            )
            case_id = _verify_lifecycle_case_id(
                vector["case_id"], expected_case_id, f"{vector_path}.case_id"
            )
            record = _verify_registration_lifecycle_case(vector, vector_path)
            prior_cases[case_id] = record
        elif request_kind == "recovery":
            vector = _require_ordered_keys(
                case_object["vector"], LIFECYCLE_RECOVERY_VECTOR_KEY_ORDER, vector_path
            )
            case_id = _verify_lifecycle_case_id(
                vector["case_id"], expected_case_id, f"{vector_path}.case_id"
            )
            record = _verify_recovery_lifecycle_case(vector, vector_path)
            prior_cases[case_id] = record
        elif request_kind == "refresh":
            vector = _require_ordered_keys(
                case_object["vector"], LIFECYCLE_REFRESH_VECTOR_KEY_ORDER, vector_path
            )
            case_id = _verify_lifecycle_case_id(
                vector["case_id"], expected_case_id, f"{vector_path}.case_id"
            )
            record = _verify_refresh_lifecycle_case(vector, vector_path)
            prior_cases[case_id] = record
        else:
            activation = _require_ordered_keys(
                case_object["vector"], LIFECYCLE_ACTIVATION_VECTOR_KEY_ORDER, vector_path
            )
            transition = _require_object(
                activation["transition"], f"{vector_path}.transition"
            )
            case_id = _verify_lifecycle_case_id(
                transition.get("case_id"), expected_case_id, f"{vector_path}.transition.case_id"
            )
            expected_origin_kind = LIFECYCLE_ACTIVATION_ORIGIN_KIND_BY_CASE_ID_V1.get(
                expected_case_id
            )
            if expected_origin_kind is None:
                raise VerificationError(
                    f"{vector_path}.transition.case_id has no canonical origin mapping"
                )
            _verify_activation_lifecycle_case(
                activation, expected_origin_kind, prior_cases, vector_path
            )
        if case_id in case_ids:
            raise VerificationError(f"{case_path} duplicates case id {case_id!r}")
        case_ids.add(case_id)

    return len(cases)


def _verify_provenance_artifact_goldens(value: Any, path: str) -> None:
    if type(value) is not list or len(value) != len(PROVENANCE_ARTIFACT_SEQUENCE_V1):
        raise VerificationError(f"{path} must contain exactly eight artifact wrappers")
    for index, ((expected_kind, expected_tag), golden) in enumerate(
        zip(PROVENANCE_ARTIFACT_SEQUENCE_V1, value)
    ):
        item_path = f"{path}[{index}]"
        item = _require_ordered_keys(
            golden, PROVENANCE_ARTIFACT_GOLDEN_KEY_ORDER, item_path
        )
        _require_exact_value(
            _require_string(item["kind"], f"{item_path}.kind"),
            expected_kind,
            f"{item_path}.kind",
        )
        _require_exact_value(
            _require_u8(item["kind_tag"], f"{item_path}.kind_tag"),
            expected_tag,
            f"{item_path}.kind_tag",
        )
        artifact = _decode_variable_hex(
            item["canonical_artifact_hex"], f"{item_path}.canonical_artifact_hex"
        )
        wrapper = _lp32_join(
            (PROVENANCE_ARTIFACT_DIGEST_DOMAIN_V1, bytes((expected_tag,)), artifact)
        )
        _require_expected_bytes(
            item["digest_sha256_hex"],
            hashlib.sha256(wrapper).digest(),
            f"{item_path}.digest_sha256_hex",
        )


def _verify_provenance_stable_scope(encoded: bytes, path: str) -> tuple[Any, ...]:
    fields = _parse_lp32_fields(encoded, 5, path)
    _require_bytes(fields[0], PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1, f"{path}.domain")
    application_digest = _require_fixed_bytes(
        fields[1], 32, f"{path}.application_binding_digest"
    )
    participant_low = int.from_bytes(
        _require_fixed_bytes(fields[2], 2, f"{path}.participant_low"), "big"
    )
    participant_high = int.from_bytes(
        _require_fixed_bytes(fields[3], 2, f"{path}.participant_high"), "big"
    )
    if participant_low == 0 or participant_low >= participant_high:
        raise VerificationError(f"{path} participant identifiers are not canonical")
    binding_digest = _require_fixed_bytes(
        fields[4], 32, f"{path}.stable_context_binding_digest"
    )
    context_encoding = (
        STABLE_CONTEXT_DOMAIN_V1
        + application_digest
        + participant_low.to_bytes(2, "big")
        + participant_high.to_bytes(2, "big")
    )
    expected_binding = hashlib.sha256(
        STABLE_CONTEXT_BINDING_DOMAIN_V1 + context_encoding
    ).digest()
    if binding_digest != expected_binding:
        raise VerificationError(f"{path}.stable_context_binding_digest does not match")
    return application_digest, participant_low, participant_high, binding_digest


def _verify_provenance_ceremony(
    encoded: bytes, request_tag: int, path: str
) -> tuple[bytes, ...]:
    fields = _parse_lp32_fields(encoded, 7, path)
    _require_bytes(
        fields[0], PROVENANCE_CEREMONY_BINDING_ENCODING_DOMAIN_V1, f"{path}.domain"
    )
    _require_bytes(fields[1], bytes((request_tag,)), f"{path}.request_kind")
    labels = (
        "public_request_context_digest",
        "transcript_digest",
        "authorization_digest",
        "client_envelope_artifact_digest",
        "client_envelope_set_digest",
    )
    return tuple(
        _require_fixed_bytes(field, 32, f"{path}.{label}")
        for label, field in zip(labels, fields[2:])
    )


def _verify_provenance_snapshot(encoded: bytes, path: str) -> dict[str, Any]:
    fields = _parse_lp32_fields(encoded, 9, path)
    _require_bytes(
        fields[0], PROVENANCE_ROLE_INPUT_SNAPSHOT_ENCODING_DOMAIN_V1, f"{path}.domain"
    )
    labels = (
        "role_root_record_digest",
        "root_binding_artifact_digest",
        "role_input_state_record_digest",
        "client_input_artifact_digest",
        "server_input_artifact_digest",
        "combined_input_artifact_digest",
    )
    for label, field in zip(labels[:2], fields[1:3]):
        _require_fixed_bytes(field, 32, f"{path}.{label}")
    root_epoch = int.from_bytes(
        _require_fixed_bytes(fields[3], 8, f"{path}.role_root_epoch"), "big"
    )
    if root_epoch == 0:
        raise VerificationError(f"{path}.role_root_epoch must be nonzero")
    _require_fixed_bytes(fields[4], 32, f"{path}.{labels[2]}")
    input_state_epoch = int.from_bytes(
        _require_fixed_bytes(fields[5], 8, f"{path}.role_input_state_epoch"), "big"
    )
    if input_state_epoch == 0:
        raise VerificationError(f"{path}.role_input_state_epoch must be nonzero")
    for label, field in zip(labels[3:], fields[6:]):
        _require_fixed_bytes(field, 32, f"{path}.{label}")
    return {
        "encoding": encoded,
        "role_root_record_digest": fields[1],
        "root_epoch": root_epoch,
        "input_state_epoch": input_state_epoch,
    }


def _verify_provenance_snapshot_list(value: Any, path: str) -> tuple[bytes, ...]:
    if type(value) is not list:
        raise VerificationError(f"{path} must be a JSON array")
    return tuple(
        _decode_variable_hex(item, f"{path}[{index}]") for index, item in enumerate(value)
    )


def _verify_provenance_branch(
    request_kind: str,
    encoded: bytes,
    listed_snapshots: tuple[bytes, ...],
    path: str,
) -> dict[str, Any]:
    if request_kind == "registration":
        fields = _parse_lp32_fields(encoded, 4, path)
        _require_bytes(
            fields[0], PROVENANCE_REGISTRATION_BRANCH_ENCODING_DOMAIN_V1, f"{path}.domain"
        )
        snapshots = (_verify_provenance_snapshot(fields[1], f"{path}.initial_snapshot"),)
        intent = _require_fixed_bytes(fields[2], 32, f"{path}.intent_digest")
        anti_bias = _require_fixed_bytes(
            fields[3], 32, f"{path}.anti_bias_artifact_digest"
        )
        joint = (intent, anti_bias)
    elif request_kind == "recovery":
        fields = _parse_lp32_fields(encoded, 4, path)
        _require_bytes(
            fields[0], PROVENANCE_RECOVERY_BRANCH_ENCODING_DOMAIN_V1, f"{path}.domain"
        )
        snapshots = (_verify_provenance_snapshot(fields[1], f"{path}.current_snapshot"),)
        public_key = _require_fixed_bytes(fields[2], 32, f"{path}.registered_public_key")
        _verify_registered_public_key(public_key, f"{path}.registered_public_key")
        continuity = _require_fixed_bytes(
            fields[3], 32, f"{path}.continuity_artifact_digest"
        )
        joint = (public_key, continuity)
    elif request_kind == "refresh":
        fields = _parse_lp32_fields(encoded, 5, path)
        _require_bytes(
            fields[0], PROVENANCE_REFRESH_BRANCH_ENCODING_DOMAIN_V1, f"{path}.domain"
        )
        before = _verify_provenance_snapshot(fields[1], f"{path}.before_snapshot")
        after = _verify_provenance_snapshot(fields[2], f"{path}.after_snapshot")
        snapshots = (before, after)
        if before["role_root_record_digest"] != after["role_root_record_digest"]:
            raise VerificationError(f"{path} refresh changed the role-root record")
        if before["root_epoch"] != after["root_epoch"]:
            raise VerificationError(f"{path} refresh changed the role-root epoch")
        if after["input_state_epoch"] <= before["input_state_epoch"]:
            raise VerificationError(f"{path} refresh input-state epoch did not advance")
        public_key = _require_fixed_bytes(fields[3], 32, f"{path}.registered_public_key")
        _verify_registered_public_key(public_key, f"{path}.registered_public_key")
        continuity = _require_fixed_bytes(
            fields[4], 32, f"{path}.continuity_artifact_digest"
        )
        joint = (public_key, continuity)
    elif request_kind == "export":
        fields = _parse_lp32_fields(encoded, 3, path)
        _require_bytes(
            fields[0], PROVENANCE_EXPORT_BRANCH_ENCODING_DOMAIN_V1, f"{path}.domain"
        )
        snapshots = (_verify_provenance_snapshot(fields[1], f"{path}.current_snapshot"),)
        public_key = _require_fixed_bytes(fields[2], 32, f"{path}.registered_public_key")
        _verify_registered_public_key(public_key, f"{path}.registered_public_key")
        joint = (public_key,)
    else:
        raise VerificationError(f"{path} has unsupported provenance request kind")
    snapshot_encodings = tuple(snapshot["encoding"] for snapshot in snapshots)
    if listed_snapshots != snapshot_encodings:
        raise VerificationError(f"{path} snapshot_encodings_hex does not match branch order")
    return {"joint": joint, "snapshots": snapshots}


def _provenance_family(request_kind: str) -> tuple[str, int, str]:
    if request_kind == "export":
        return "export", 0x02, EXPORT_CIRCUIT_ID_V1
    return "activation", 0x01, ACTIVATION_CIRCUIT_ID_V1


def _verify_provenance_role_statement(
    role_value: Any,
    request_kind: str,
    request_tag: int,
    expected_role_name: str,
    expected_role_tag: int,
    vector_values: dict[str, bytes],
    path: str,
) -> dict[str, Any]:
    role = _require_ordered_keys(role_value, PROVENANCE_ROLE_VECTOR_KEY_ORDER, path)
    _require_exact_value(
        _require_string(role["role"], f"{path}.role"),
        expected_role_name,
        f"{path}.role",
    )
    _require_exact_value(
        _require_u8(role["role_tag"], f"{path}.role_tag"),
        expected_role_tag,
        f"{path}.role_tag",
    )
    stable_encoding = _decode_variable_hex(
        role["stable_scope_encoding_hex"], f"{path}.stable_scope_encoding_hex"
    )
    ceremony_encoding = _decode_variable_hex(
        role["ceremony_binding_encoding_hex"],
        f"{path}.ceremony_binding_encoding_hex",
    )
    branch_encoding = _decode_variable_hex(
        role["branch_encoding_hex"], f"{path}.branch_encoding_hex"
    )
    listed_snapshots = _verify_provenance_snapshot_list(
        role["snapshot_encodings_hex"], f"{path}.snapshot_encodings_hex"
    )
    statement_encoding = _decode_variable_hex(
        role["statement_encoding_hex"], f"{path}.statement_encoding_hex"
    )
    fields = _parse_lp32_fields(statement_encoding, 11, f"{path}.statement")
    _require_bytes(
        fields[0], PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1, f"{path}.statement.domain"
    )
    _require_bytes(fields[1], PROTOCOL_ID_V1.encode(), f"{path}.statement.protocol_id")
    _require_bytes(fields[2], bytes((request_tag,)), f"{path}.statement.request_kind")
    _require_bytes(fields[3], bytes((expected_role_tag,)), f"{path}.statement.role")
    family_name, family_tag, circuit_id = _provenance_family(request_kind)
    _require_bytes(fields[4], bytes((family_tag,)), f"{path}.statement.circuit_family")
    _require_bytes(fields[5], circuit_id.encode(), f"{path}.statement.circuit_id")
    circuit_digest = _require_fixed_bytes(fields[6], 32, f"{path}.statement.circuit_digest")
    schema_digest = _require_fixed_bytes(fields[7], 32, f"{path}.statement.input_schema_digest")
    if circuit_digest == bytes(32) or schema_digest == bytes(32):
        raise VerificationError(f"{path}.statement contains a zero manifest digest")
    _require_bytes(circuit_digest, vector_values["circuit_digest"], f"{path}.circuit_digest")
    _require_bytes(schema_digest, vector_values["schema_digest"], f"{path}.schema_digest")
    _require_bytes(fields[8], stable_encoding, f"{path}.statement.stable_scope")
    _require_bytes(fields[9], ceremony_encoding, f"{path}.statement.ceremony")
    _require_bytes(fields[10], branch_encoding, f"{path}.statement.branch")
    stable = _verify_provenance_stable_scope(stable_encoding, f"{path}.stable_scope")
    ceremony = _verify_provenance_ceremony(
        ceremony_encoding, request_tag, f"{path}.ceremony"
    )
    branch = _verify_provenance_branch(
        request_kind, branch_encoding, listed_snapshots, f"{path}.branch"
    )
    statement_digest = hashlib.sha256(
        _lp32_join((PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1, statement_encoding))
    ).digest()
    _require_expected_bytes(
        role["statement_digest_sha256_hex"],
        statement_digest,
        f"{path}.statement_digest_sha256_hex",
    )
    return {
        "family_name": family_name,
        "circuit_id": circuit_id,
        "stable": stable,
        "ceremony": ceremony,
        "branch_joint": branch["joint"],
        "statement_digest": statement_digest,
    }


def _verify_provenance_case(
    value: Any,
    expected_kind: str,
    expected_case_id: str,
    expected_request_tag: int,
    path: str,
) -> None:
    case = _require_ordered_keys(value, PROVENANCE_CASE_KEY_ORDER, path)
    request_kind = _require_string(case["request_kind"], f"{path}.request_kind")
    _require_exact_value(request_kind, expected_kind, f"{path}.request_kind")
    vector_path = f"{path}.vector"
    vector = _require_ordered_keys(case["vector"], PROVENANCE_VECTOR_KEY_ORDER, vector_path)
    _require_exact_value(
        _require_string(vector["case_id"], f"{vector_path}.case_id"),
        expected_case_id,
        f"{vector_path}.case_id",
    )
    family_name, _, circuit_id = _provenance_family(request_kind)
    _require_exact_value(
        _require_string(vector["circuit_family"], f"{vector_path}.circuit_family"),
        family_name,
        f"{vector_path}.circuit_family",
    )
    _require_exact_value(
        _require_string(vector["circuit_id"], f"{vector_path}.circuit_id"),
        circuit_id,
        f"{vector_path}.circuit_id",
    )
    vector_values = {
        "circuit_digest": _decode_hex(
            vector["final_circuit_digest_hex"], 32, f"{vector_path}.final_circuit_digest_hex"
        ),
        "schema_digest": _decode_hex(
            vector["input_schema_digest_hex"], 32, f"{vector_path}.input_schema_digest_hex"
        ),
        "request_context": _decode_hex(
            vector["public_request_context_digest_hex"],
            32,
            f"{vector_path}.public_request_context_digest_hex",
        ),
        "transcript": _decode_hex(
            vector["transcript_digest_hex"], 32, f"{vector_path}.transcript_digest_hex"
        ),
        "authorization": _decode_hex(
            vector["authorization_digest_hex"], 32, f"{vector_path}.authorization_digest_hex"
        ),
        "envelope_a": _decode_hex(
            vector["client_envelope_a_artifact_digest_hex"],
            32,
            f"{vector_path}.client_envelope_a_artifact_digest_hex",
        ),
        "envelope_b": _decode_hex(
            vector["client_envelope_b_artifact_digest_hex"],
            32,
            f"{vector_path}.client_envelope_b_artifact_digest_hex",
        ),
        "envelope_set": _decode_hex(
            vector["client_envelope_set_digest_hex"],
            32,
            f"{vector_path}.client_envelope_set_digest_hex",
        ),
    }
    a = _verify_provenance_role_statement(
        vector["deriver_a"],
        request_kind,
        expected_request_tag,
        "deriver_a",
        0x01,
        vector_values,
        f"{vector_path}.deriver_a",
    )
    b = _verify_provenance_role_statement(
        vector["deriver_b"],
        request_kind,
        expected_request_tag,
        "deriver_b",
        0x02,
        vector_values,
        f"{vector_path}.deriver_b",
    )
    if a["family_name"] != b["family_name"] or a["circuit_id"] != b["circuit_id"]:
        raise VerificationError(f"{vector_path} A/B circuit families differ")
    if a["stable"] != b["stable"]:
        raise VerificationError(f"{vector_path} A/B stable scopes differ")
    ceremony_a = a["ceremony"]
    ceremony_b = b["ceremony"]
    for index, label in ((0, "request context"), (1, "transcript"), (2, "authorization"), (4, "envelope set")):
        if ceremony_a[index] != ceremony_b[index]:
            raise VerificationError(f"{vector_path} A/B {label} digests differ")
    expected_ceremony = (
        vector_values["request_context"],
        vector_values["transcript"],
        vector_values["authorization"],
    )
    if ceremony_a[:3] != expected_ceremony:
        raise VerificationError(f"{vector_path} ceremony digests do not match vector fields")
    if ceremony_a[3] != vector_values["envelope_a"]:
        raise VerificationError(f"{vector_path} Deriver A envelope digest does not match")
    if ceremony_b[3] != vector_values["envelope_b"]:
        raise VerificationError(f"{vector_path} Deriver B envelope digest does not match")
    if ceremony_a[4] != vector_values["envelope_set"]:
        raise VerificationError(f"{vector_path} envelope-set digest does not match")
    expected_envelope_set = hashlib.sha256(
        _lp32_join(
            (
                PROVENANCE_CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1,
                vector_values["envelope_a"],
                vector_values["envelope_b"],
            )
        )
    ).digest()
    if vector_values["envelope_set"] != expected_envelope_set:
        raise VerificationError(f"{vector_path} envelope-set digest is not fixed A-then-B order")
    if a["branch_joint"] != b["branch_joint"]:
        raise VerificationError(f"{vector_path} A/B branch joint fields differ")

    pair_encoding = _decode_variable_hex(
        vector["pair_encoding_hex"], f"{vector_path}.pair_encoding_hex"
    )
    pair_fields = _parse_lp32_fields(pair_encoding, 3, f"{vector_path}.pair")
    _require_bytes(
        pair_fields[0], PROVENANCE_PAIR_ENCODING_DOMAIN_V1, f"{vector_path}.pair.domain"
    )
    _require_bytes(
        pair_fields[1], a["statement_digest"], f"{vector_path}.pair.deriver_a_digest"
    )
    _require_bytes(
        pair_fields[2], b["statement_digest"], f"{vector_path}.pair.deriver_b_digest"
    )
    pair_digest = hashlib.sha256(
        _lp32_join((PROVENANCE_PAIR_DIGEST_DOMAIN_V1, pair_encoding))
    ).digest()
    _require_expected_bytes(
        vector["pair_digest_sha256_hex"],
        pair_digest,
        f"{vector_path}.pair_digest_sha256_hex",
    )


def _verify_provenance_outer_corpus(corpus: Any) -> int:
    """Structurally verifies the fixed host-only provenance outer corpus."""
    corpus_object = _require_ordered_keys(corpus, PROVENANCE_CORPUS_KEY_ORDER, "$")
    _require_exact_value(
        _require_string(corpus_object["schema"], "$.schema"),
        PROVENANCE_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(corpus_object["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(corpus_object["evidence_scope"], "$.evidence_scope"),
        PROVENANCE_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    _verify_provenance_artifact_goldens(
        corpus_object["artifact_wrapper_goldens"], "$.artifact_wrapper_goldens"
    )
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) != len(PROVENANCE_CASE_SEQUENCE_V1):
        raise VerificationError("$.cases must contain exactly four provenance cases")
    for index, ((request_kind, case_id, request_tag), case) in enumerate(
        zip(PROVENANCE_CASE_SEQUENCE_V1, cases)
    ):
        _verify_provenance_case(
            case, request_kind, case_id, request_tag, f"$.cases[{index}]"
        )
    return len(cases)


def _verify_output_sharing_source_reference(
    value: Any, expected_case_id: str, path: str
) -> tuple[bytes, int, int]:
    source = _require_ordered_keys(
        value, OUTPUT_SHARING_SOURCE_REFERENCE_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(source["case_id"], f"{path}.case_id"),
        expected_case_id,
        f"{path}.case_id",
    )
    inputs_path = f"{path}.inputs"
    inputs = _require_ordered_keys(
        source["inputs"], OUTPUT_SHARING_INPUT_KEY_ORDER, inputs_path
    )
    expected_inputs = OUTPUT_SHARING_SOURCE_INPUTS_V1[expected_case_id]
    decoded_seed_parts: dict[str, bytes] = {}
    decoded_scalar_parts: dict[str, int] = {}
    for index, field_name in enumerate(OUTPUT_SHARING_INPUT_KEY_ORDER):
        field_path = f"{inputs_path}.{field_name}"
        if field_name.startswith("tau_"):
            scalar = _decode_scalar(inputs[field_name], field_path)
            decoded_scalar_parts[field_name] = scalar
            actual_bytes = scalar.to_bytes(32, "little")
        else:
            seed_part = _decode_hex(inputs[field_name], 32, field_path)
            decoded_seed_parts[field_name] = seed_part
            actual_bytes = seed_part
        if actual_bytes != bytes.fromhex(expected_inputs[index]):
            raise VerificationError(
                f"{field_path} does not match source case {expected_case_id!r}"
            )

    y_a = _wrapping_add_256(
        decoded_seed_parts["y_client_a_hex"], decoded_seed_parts["y_server_a_hex"]
    )
    y_b = _wrapping_add_256(
        decoded_seed_parts["y_client_b_hex"], decoded_seed_parts["y_server_b_hex"]
    )
    joined_seed = _wrapping_add_256(y_a, y_b)
    sha512_digest = hashlib.sha512(joined_seed).digest()
    clamped_scalar_bytes = bytearray(sha512_digest[:32])
    clamped_scalar_bytes[0] &= 248
    clamped_scalar_bytes[31] &= 63
    clamped_scalar_bytes[31] |= 64
    signing_scalar = int.from_bytes(clamped_scalar_bytes, "little") % SCALAR_ORDER
    tau_a = (
        decoded_scalar_parts["tau_client_a_hex"]
        + decoded_scalar_parts["tau_server_a_hex"]
    ) % SCALAR_ORDER
    tau_b = (
        decoded_scalar_parts["tau_client_b_hex"]
        + decoded_scalar_parts["tau_server_b_hex"]
    ) % SCALAR_ORDER
    tau = (tau_a + tau_b) % SCALAR_ORDER
    x_client_base = (signing_scalar + tau) % SCALAR_ORDER
    x_server_base = (signing_scalar + 2 * tau) % SCALAR_ORDER
    return joined_seed, x_client_base, x_server_base


def _verify_output_sharing_activation_case(
    case: dict[str, Any],
    expected_case_id: str,
    expected_request_kind: str,
    expected_source_case_id: str,
    expected_coins: tuple[int, int],
    path: str,
) -> None:
    vector_path = f"{path}.vector"
    vector = _require_ordered_keys(
        case["vector"], OUTPUT_SHARING_ACTIVATION_VECTOR_KEY_ORDER, vector_path
    )
    _require_exact_value(
        _require_string(vector["case_id"], f"{vector_path}.case_id"),
        expected_case_id,
        f"{vector_path}.case_id",
    )
    _require_exact_value(
        _require_string(vector["request_kind"], f"{vector_path}.request_kind"),
        expected_request_kind,
        f"{vector_path}.request_kind",
    )
    _, expected_client, expected_signing_worker = (
        _verify_output_sharing_source_reference(
            vector["host_only_source_reference"],
            expected_source_case_id,
            f"{vector_path}.host_only_source_reference",
        )
    )

    joined_path = f"{vector_path}.host_only_joined_outputs"
    joined = _require_ordered_keys(
        vector["host_only_joined_outputs"],
        OUTPUT_SHARING_ACTIVATION_JOINED_KEY_ORDER,
        joined_path,
    )
    x_client_base = _decode_scalar(
        joined["x_client_base_hex"], f"{joined_path}.x_client_base_hex"
    )
    x_signing_worker_base = _decode_scalar(
        joined["x_server_base_hex"], f"{joined_path}.x_server_base_hex"
    )
    if x_client_base != expected_client:
        raise VerificationError(
            f"{joined_path}.x_client_base_hex does not match the copied source inputs"
        )
    if x_signing_worker_base != expected_signing_worker:
        raise VerificationError(
            f"{joined_path}.x_server_base_hex does not match the copied source inputs"
        )

    randomness_path = f"{vector_path}.host_only_reference_randomness"
    randomness = _require_ordered_keys(
        vector["host_only_reference_randomness"],
        OUTPUT_SHARING_ACTIVATION_RANDOMNESS_KEY_ORDER,
        randomness_path,
    )
    client_coin = _decode_scalar(
        randomness["r_client_hex"], f"{randomness_path}.r_client_hex"
    )
    signing_worker_coin = _decode_scalar(
        randomness["r_signing_worker_hex"],
        f"{randomness_path}.r_signing_worker_hex",
    )
    if (client_coin, signing_worker_coin) != expected_coins:
        raise VerificationError(
            f"{randomness_path} does not contain the frozen fixture coins"
        )

    shares_path = f"{vector_path}.role_output_shares"
    shares = _require_ordered_keys(
        vector["role_output_shares"], OUTPUT_SHARING_ROLE_OUTPUT_KEY_ORDER, shares_path
    )
    deriver_a_path = f"{shares_path}.deriver_a"
    deriver_a = _require_ordered_keys(
        shares["deriver_a"],
        OUTPUT_SHARING_ACTIVATION_ROLE_SHARE_KEY_ORDER,
        deriver_a_path,
    )
    deriver_b_path = f"{shares_path}.deriver_b"
    deriver_b = _require_ordered_keys(
        shares["deriver_b"],
        OUTPUT_SHARING_ACTIVATION_ROLE_SHARE_KEY_ORDER,
        deriver_b_path,
    )
    a_client = _decode_scalar(
        deriver_a["client_scalar_share_hex"],
        f"{deriver_a_path}.client_scalar_share_hex",
    )
    a_signing_worker = _decode_scalar(
        deriver_a["signing_worker_scalar_share_hex"],
        f"{deriver_a_path}.signing_worker_scalar_share_hex",
    )
    b_client = _decode_scalar(
        deriver_b["client_scalar_share_hex"],
        f"{deriver_b_path}.client_scalar_share_hex",
    )
    b_signing_worker = _decode_scalar(
        deriver_b["signing_worker_scalar_share_hex"],
        f"{deriver_b_path}.signing_worker_scalar_share_hex",
    )
    if a_client != client_coin or a_signing_worker != signing_worker_coin:
        raise VerificationError(
            f"{shares_path}.deriver_a shares must equal the branch-specific fixture coins"
        )
    if b_client != (x_client_base - client_coin) % SCALAR_ORDER:
        raise VerificationError(
            f"{deriver_b_path}.client_scalar_share_hex violates the sharing equation"
        )
    if b_signing_worker != (
        x_signing_worker_base - signing_worker_coin
    ) % SCALAR_ORDER:
        raise VerificationError(
            f"{deriver_b_path}.signing_worker_scalar_share_hex violates the sharing equation"
        )
    if (a_client + b_client) % SCALAR_ORDER != x_client_base:
        raise VerificationError(f"{shares_path} does not reconstruct x_client_base")
    if (
        a_signing_worker + b_signing_worker
    ) % SCALAR_ORDER != x_signing_worker_base:
        raise VerificationError(f"{shares_path} does not reconstruct x_server_base")


def _verify_output_sharing_export_case(
    case: dict[str, Any],
    expected_case_id: str,
    expected_source_case_id: str,
    expected_coin: int,
    path: str,
) -> None:
    vector_path = f"{path}.vector"
    vector = _require_ordered_keys(
        case["vector"], OUTPUT_SHARING_EXPORT_VECTOR_KEY_ORDER, vector_path
    )
    _require_exact_value(
        _require_string(vector["case_id"], f"{vector_path}.case_id"),
        expected_case_id,
        f"{vector_path}.case_id",
    )
    expected_seed, _, _ = _verify_output_sharing_source_reference(
        vector["host_only_source_reference"],
        expected_source_case_id,
        f"{vector_path}.host_only_source_reference",
    )

    joined_path = f"{vector_path}.host_only_joined_output"
    joined = _require_ordered_keys(
        vector["host_only_joined_output"],
        OUTPUT_SHARING_EXPORT_JOINED_KEY_ORDER,
        joined_path,
    )
    joined_seed = _decode_hex(
        joined["joined_seed_hex"], 32, f"{joined_path}.joined_seed_hex"
    )
    if joined_seed != expected_seed:
        raise VerificationError(
            f"{joined_path}.joined_seed_hex does not match the copied source inputs"
        )

    randomness_path = f"{vector_path}.host_only_reference_randomness"
    randomness = _require_ordered_keys(
        vector["host_only_reference_randomness"],
        OUTPUT_SHARING_EXPORT_RANDOMNESS_KEY_ORDER,
        randomness_path,
    )
    coin = _decode_hex(randomness["u_hex"], 32, f"{randomness_path}.u_hex")
    expected_coin_bytes = expected_coin.to_bytes(32, "little")
    if coin != expected_coin_bytes:
        raise VerificationError(
            f"{randomness_path}.u_hex does not contain the frozen fixture coin"
        )

    shares_path = f"{vector_path}.role_output_shares"
    shares = _require_ordered_keys(
        vector["role_output_shares"], OUTPUT_SHARING_ROLE_OUTPUT_KEY_ORDER, shares_path
    )
    deriver_a_path = f"{shares_path}.deriver_a"
    deriver_a = _require_ordered_keys(
        shares["deriver_a"],
        OUTPUT_SHARING_EXPORT_ROLE_SHARE_KEY_ORDER,
        deriver_a_path,
    )
    deriver_b_path = f"{shares_path}.deriver_b"
    deriver_b = _require_ordered_keys(
        shares["deriver_b"],
        OUTPUT_SHARING_EXPORT_ROLE_SHARE_KEY_ORDER,
        deriver_b_path,
    )
    a_seed = _decode_hex(
        deriver_a["seed_share_hex"], 32, f"{deriver_a_path}.seed_share_hex"
    )
    b_seed = _decode_hex(
        deriver_b["seed_share_hex"], 32, f"{deriver_b_path}.seed_share_hex"
    )
    if a_seed != coin:
        raise VerificationError(
            f"{deriver_a_path}.seed_share_hex must equal the export fixture coin"
        )
    joined_integer = int.from_bytes(joined_seed, "little")
    coin_integer = int.from_bytes(coin, "little")
    b_integer = int.from_bytes(b_seed, "little")
    expected_b = (joined_integer - coin_integer) & SEED_MODULUS_MASK
    if b_integer != expected_b:
        raise VerificationError(
            f"{deriver_b_path}.seed_share_hex violates the seed-sharing equation"
        )
    a_integer = int.from_bytes(a_seed, "little")
    if (a_integer + b_integer) & SEED_MODULUS_MASK != joined_integer:
        raise VerificationError(f"{shares_path} does not reconstruct the joined seed")


def verify_output_sharing_corpus(corpus: Any) -> int:
    """Independently verifies the fixed host-only output-sharing corpus."""
    corpus_object = _require_ordered_keys(
        corpus, OUTPUT_SHARING_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(corpus_object["schema"], "$.schema"),
        OUTPUT_SHARING_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(corpus_object["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(corpus_object["evidence_scope"], "$.evidence_scope"),
        OUTPUT_SHARING_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) != len(OUTPUT_SHARING_CASE_SEQUENCE_V1):
        raise VerificationError("$.cases must contain exactly six output-sharing cases")

    for index, expected in enumerate(OUTPUT_SHARING_CASE_SEQUENCE_V1):
        output_family, case_id, request_kind, source_case_id = expected
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], OUTPUT_SHARING_CASE_KEY_ORDER, case_path
        )
        _require_exact_value(
            _require_string(case["output_family"], f"{case_path}.output_family"),
            output_family,
            f"{case_path}.output_family",
        )
        if output_family == "activation":
            if request_kind is None:
                raise VerificationError("internal activation case lacks a request kind")
            _verify_output_sharing_activation_case(
                case,
                case_id,
                request_kind,
                source_case_id,
                OUTPUT_SHARING_ACTIVATION_COINS_V1[index],
                case_path,
            )
        else:
            _verify_output_sharing_export_case(
                case,
                case_id,
                source_case_id,
                OUTPUT_SHARING_EXPORT_COINS_V1[index - 3],
                case_path,
            )
    return len(cases)


def _ceremony_visible_ascii(value: Any, path: str) -> bytes:
    identifier = _require_string(value, path)
    if not identifier:
        raise VerificationError(f"{path} must be nonempty")
    try:
        encoded = identifier.encode("ascii")
    except UnicodeEncodeError as error:
        raise VerificationError(f"{path} must contain only visible ASCII bytes") from error
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise VerificationError(f"{path} must contain only visible ASCII bytes")
    return encoded


def _ceremony_positive_u64(value: Any, path: str) -> bytes:
    if type(value) is not int or not 1 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise VerificationError(f"{path} must be a positive u64")
    return value.to_bytes(8, "big")


def _ceremony_nonzero_digest(value: Any, path: str) -> bytes:
    digest = _decode_hex(value, 32, path)
    if digest == bytes(32):
        raise VerificationError(f"{path} must be nonzero")
    return digest


def _ceremony_labeled(fields: Sequence[tuple[bytes, bytes]]) -> tuple[bytes, ...]:
    flattened: list[bytes] = []
    for label, value in fields:
        flattened.extend((label, value))
    return tuple(flattened)


def _require_visible_ascii_bytes(value: bytes, path: str) -> None:
    if not value or any(byte < 0x21 or byte > 0x7E for byte in value):
        raise VerificationError(f"{path} must contain nonempty visible ASCII bytes")


def _require_fixed_bytes(value: bytes, length: int, path: str) -> bytes:
    if len(value) != length:
        raise VerificationError(f"{path} must contain exactly {length} bytes")
    return value


def _require_nonzero_bytes(value: bytes, length: int, path: str) -> bytes:
    _require_fixed_bytes(value, length, path)
    if value == bytes(length):
        raise VerificationError(f"{path} must be nonzero")
    return value


def _require_positive_be64(value: bytes, path: str) -> int:
    _require_fixed_bytes(value, 8, path)
    decoded = int.from_bytes(value, "big")
    if decoded == 0:
        raise VerificationError(f"{path} must be a positive BE64 value")
    return decoded


def _parse_labeled_lp32_encoding(
    encoded: bytes,
    domain: bytes,
    labels: Sequence[bytes],
    path: str,
) -> dict[bytes, bytes]:
    fields = _parse_lp32_fields(encoded, 1 + 2 * len(labels), path)
    if fields[0] != domain:
        raise VerificationError(f"{path} has the wrong encoding domain")
    parsed: dict[bytes, bytes] = {}
    for index, expected_label in enumerate(labels):
        label = fields[1 + index * 2]
        value = fields[2 + index * 2]
        if label != expected_label:
            raise VerificationError(
                f"{path} label {index} must equal {expected_label!r}"
            )
        parsed[expected_label] = value
    if _lp32_join(fields) != encoded:
        raise VerificationError(f"{path} is not canonical LP32")
    return parsed


def _scan_semantic_lifecycle_public_boundary(value: Any, path: str) -> None:
    if type(value) is dict:
        for key, nested in value.items():
            if any(
                fragment in key
                for fragment in SEMANTIC_LIFECYCLE_FORBIDDEN_FIELD_FRAGMENTS_V1
            ):
                raise VerificationError(
                    f"{path}.{key} is forbidden in the public semantic lifecycle corpus"
                )
            _scan_semantic_lifecycle_public_boundary(nested, f"{path}.{key}")
        return
    if type(value) is list:
        for index, nested in enumerate(value):
            _scan_semantic_lifecycle_public_boundary(nested, f"{path}[{index}]")


def _verify_ceremony_request_context(
    source: Any,
    expected: dict[str, Any],
    request_kind: str,
    path: str,
) -> bytes:
    context = _require_ordered_keys(
        source, CEREMONY_PUBLIC_REQUEST_CONTEXT_KEY_ORDER, path
    )
    kind_tag, recipient_name, recipient_tag, output_name, output_tag, _ = (
        CEREMONY_KIND_METADATA_V1[request_kind]
    )
    protocol_version = _ceremony_positive_u64(
        context["protocol_version"], f"{path}.protocol_version"
    )
    if protocol_version != (1).to_bytes(8, "big"):
        raise VerificationError(f"{path}.protocol_version must equal 1")

    text_fields = {
        name: _ceremony_visible_ascii(context[name], f"{path}.{name}")
        for name in (
            "request_id",
            "account_id",
            "wallet_id",
            "session_id",
            "organization_id",
            "project_id",
            "environment_id",
            "signing_root_id",
            "chain_target",
            "router_id",
            "deriver_set_id",
            "deriver_a_id",
            "deriver_b_id",
            "signing_worker_id",
        )
    }
    replay_nonce = _decode_hex(
        context["replay_nonce_hex"], 32, f"{path}.replay_nonce_hex"
    )
    client_ephemeral_key = _decode_hex(
        context["client_ephemeral_public_key_hex"],
        32,
        f"{path}.client_ephemeral_public_key_hex",
    )
    recipient_plan = _require_string(
        context["recipient_plan"], f"{path}.recipient_plan"
    )
    if recipient_plan != recipient_name:
        raise VerificationError(
            f"{path}.recipient_plan does not match the request kind"
        )
    output_package_kind = _require_string(
        context["output_package_kind"], f"{path}.output_package_kind"
    )
    if output_package_kind != output_name:
        raise VerificationError(
            f"{path}.output_package_kind does not match the request kind"
        )

    numeric_fields = {
        name: _ceremony_positive_u64(context[name], f"{path}.{name}")
        for name in (
            "signing_root_version",
            "root_share_epoch",
            "deriver_a_key_epoch",
            "deriver_b_key_epoch",
            "signing_worker_key_epoch",
            "request_expiry",
        )
    }
    labeled = _ceremony_labeled(
        (
            (b"protocolVersion", protocol_version),
            (b"requestKind", bytes((kind_tag,))),
            (b"requestId", text_fields["request_id"]),
            (b"replayNonce", replay_nonce),
            (b"accountId", text_fields["account_id"]),
            (b"walletId", text_fields["wallet_id"]),
            (b"sessionId", text_fields["session_id"]),
            (b"organizationId", text_fields["organization_id"]),
            (b"projectId", text_fields["project_id"]),
            (b"environmentId", text_fields["environment_id"]),
            (b"signingRootId", text_fields["signing_root_id"]),
            (b"signingRootVersion", numeric_fields["signing_root_version"]),
            (b"chainTarget", text_fields["chain_target"]),
            (b"rootShareEpoch", numeric_fields["root_share_epoch"]),
            (b"routerId", text_fields["router_id"]),
            (b"deriverSetId", text_fields["deriver_set_id"]),
            (b"deriverAId", text_fields["deriver_a_id"]),
            (b"deriverAKeyEpoch", numeric_fields["deriver_a_key_epoch"]),
            (b"deriverBId", text_fields["deriver_b_id"]),
            (b"deriverBKeyEpoch", numeric_fields["deriver_b_key_epoch"]),
            (b"signingWorkerId", text_fields["signing_worker_id"]),
            (
                b"signingWorkerKeyEpoch",
                numeric_fields["signing_worker_key_epoch"],
            ),
            (b"clientEphemeralPublicKey", client_ephemeral_key),
            (b"recipientPlan", bytes((recipient_tag,))),
            (b"outputPackageKind", bytes((output_tag,))),
            (b"requestExpiry", numeric_fields["request_expiry"]),
        )
    )
    encoding = _lp32_join((PUBLIC_REQUEST_CONTEXT_ENCODING_DOMAIN_V1, *labeled))
    _require_expected_bytes(
        expected["public_request_context_encoding_hex"],
        encoding,
        f"{path}.expected.public_request_context_encoding_hex",
    )
    digest = hashlib.sha256(encoding).digest()
    _require_expected_bytes(
        expected["public_request_context_digest_sha256_hex"],
        digest,
        f"{path}.expected.public_request_context_digest_sha256_hex",
    )
    return digest


def _verify_ceremony_authorization(
    source: Any,
    expected: dict[str, Any],
    request_kind: str,
    request_context_digest: bytes,
    registration_origin: tuple[bytes, bytes] | None,
    path: str,
) -> bytes:
    authorization = _require_ordered_keys(
        source, CEREMONY_AUTHORIZATION_KEY_ORDERS[request_kind], path
    )
    authorization_record = _ceremony_nonzero_digest(
        authorization["authorization_record_digest_hex"],
        f"{path}.authorization_record_digest_hex",
    )
    branch_fields: list[tuple[bytes, bytes]] = [
        (b"authorizationRecordDigest", authorization_record)
    ]
    if request_kind == "registration":
        branch_fields.append(
            (
                b"registrationIntentDigest",
                _ceremony_nonzero_digest(
                    authorization["registration_intent_digest_hex"],
                    f"{path}.registration_intent_digest_hex",
                ),
            )
        )
    elif request_kind == "activation":
        if registration_origin is None:
            raise VerificationError("activation requires the preceding registration origin")
        origin_context = _decode_hex(
            authorization["origin_request_context_digest_hex"],
            32,
            f"{path}.origin_request_context_digest_hex",
        )
        origin_transcript = _decode_hex(
            authorization["origin_transcript_digest_hex"],
            32,
            f"{path}.origin_transcript_digest_hex",
        )
        origin_request_kind = _require_string(
            authorization["origin_request_kind"], f"{path}.origin_request_kind"
        )
        if origin_request_kind != "registration":
            raise VerificationError(
                f"{path}.origin_request_kind must bind the canonical registration origin"
            )
        if (origin_context, origin_transcript) != registration_origin:
            raise VerificationError(
                f"{path} does not bind the registration request and transcript"
            )
        if origin_context == request_context_digest:
            raise VerificationError(
                f"{path} must not reuse the activation control request context as its origin"
            )
        branch_fields.extend(
            (
                (
                    b"originRequestKind",
                    bytes((CEREMONY_KIND_METADATA_V1[origin_request_kind][0],)),
                ),
                (b"originRequestContextDigest", origin_context),
                (b"originTranscriptDigest", origin_transcript),
                (
                    b"packageSetDigest",
                    _ceremony_nonzero_digest(
                        authorization["package_set_digest_hex"],
                        f"{path}.package_set_digest_hex",
                    ),
                ),
                (
                    b"activationEpoch",
                    _ceremony_positive_u64(
                        authorization["activation_epoch"],
                        f"{path}.activation_epoch",
                    ),
                ),
            )
        )
    elif request_kind == "recovery":
        branch_fields.append(
            (
                b"replacementCredentialBindingDigest",
                _ceremony_nonzero_digest(
                    authorization["replacement_credential_binding_digest_hex"],
                    f"{path}.replacement_credential_binding_digest_hex",
                ),
            )
        )
    elif request_kind == "refresh":
        current_a = _ceremony_positive_u64(
            authorization["current_deriver_a_input_state_epoch"],
            f"{path}.current_deriver_a_input_state_epoch",
        )
        next_a = _ceremony_positive_u64(
            authorization["next_deriver_a_input_state_epoch"],
            f"{path}.next_deriver_a_input_state_epoch",
        )
        current_b = _ceremony_positive_u64(
            authorization["current_deriver_b_input_state_epoch"],
            f"{path}.current_deriver_b_input_state_epoch",
        )
        next_b = _ceremony_positive_u64(
            authorization["next_deriver_b_input_state_epoch"],
            f"{path}.next_deriver_b_input_state_epoch",
        )
        if next_a <= current_a or next_b <= current_b:
            raise VerificationError(f"{path} role input-state epochs must advance")
        branch_fields.extend(
            (
                (b"currentDeriverAInputStateEpoch", current_a),
                (b"nextDeriverAInputStateEpoch", next_a),
                (b"currentDeriverBInputStateEpoch", current_b),
                (b"nextDeriverBInputStateEpoch", next_b),
            )
        )
    else:
        public_key = _decode_hex(
            authorization["registered_ed25519_public_key_hex"],
            32,
            f"{path}.registered_ed25519_public_key_hex",
        )
        _verify_registered_public_key(
            public_key, f"{path}.registered_ed25519_public_key_hex"
        )
        branch_fields.append((b"registeredEd25519PublicKey", public_key))

    kind_tag = CEREMONY_KIND_METADATA_V1[request_kind][0]
    labeled = _ceremony_labeled(
        (
            (b"requestKind", bytes((kind_tag,))),
            (b"publicRequestContextDigest", request_context_digest),
            *branch_fields,
        )
    )
    encoding = _lp32_join((CEREMONY_AUTHORIZATION_DOMAINS_V1[request_kind], *labeled))
    _require_expected_bytes(
        expected["authorization_encoding_hex"],
        encoding,
        f"{path}.expected.authorization_encoding_hex",
    )
    digest = hashlib.sha256(encoding).digest()
    _require_expected_bytes(
        expected["authorization_digest_sha256_hex"],
        digest,
        f"{path}.expected.authorization_digest_sha256_hex",
    )
    return digest


def _verify_ceremony_transcript(
    source: Any,
    expected: dict[str, Any],
    request_kind: str,
    request_context_digest: bytes,
    authorization_digest: bytes,
    path: str,
) -> bytes:
    transcript = _require_ordered_keys(
        source, CEREMONY_TRANSCRIPT_INPUT_KEY_ORDER, path
    )
    transcript_nonce = _decode_hex(
        transcript["transcript_nonce_hex"], 32, f"{path}.transcript_nonce_hex"
    )
    transport_digest = _ceremony_nonzero_digest(
        transcript["transport_binding_digest_hex"],
        f"{path}.transport_binding_digest_hex",
    )
    artifact_digest = _ceremony_nonzero_digest(
        transcript["artifact_suite_digest_hex"],
        f"{path}.artifact_suite_digest_hex",
    )
    kind_tag, _, _, _, _, circuit_id = CEREMONY_KIND_METADATA_V1[request_kind]
    labeled = _ceremony_labeled(
        (
            (b"protocolVersion", (1).to_bytes(8, "big")),
            (b"protocolId", PROTOCOL_ID_V1.encode("ascii")),
            (b"requestKind", bytes((kind_tag,))),
            (b"circuitId", circuit_id.encode("ascii")),
            (b"publicRequestContextDigest", request_context_digest),
            (b"authorizationDigest", authorization_digest),
            (b"transcriptNonce", transcript_nonce),
            (b"transportBindingDigest", transport_digest),
            (b"artifactSuiteDigest", artifact_digest),
        )
    )
    encoding = _lp32_join((CEREMONY_TRANSCRIPT_ENCODING_DOMAIN_V1, *labeled))
    _require_expected_bytes(
        expected["transcript_encoding_hex"],
        encoding,
        f"{path}.expected.transcript_encoding_hex",
    )
    digest = hashlib.sha256(encoding).digest()
    _require_expected_bytes(
        expected["transcript_digest_sha256_hex"],
        digest,
        f"{path}.expected.transcript_digest_sha256_hex",
    )
    return digest


def _semantic_lifecycle_kind_from_tag(tag: bytes, path: str) -> str:
    _require_fixed_bytes(tag, 1, path)
    for request_kind, metadata in CEREMONY_KIND_METADATA_V1.items():
        if tag[0] == metadata[0]:
            return request_kind
    raise VerificationError(f"{path} is not a canonical request-kind tag")


def _parse_semantic_request_context_encoding(
    encoded: bytes, request_kind: str, path: str
) -> dict[bytes, bytes]:
    fields = _parse_labeled_lp32_encoding(
        encoded,
        PUBLIC_REQUEST_CONTEXT_ENCODING_DOMAIN_V1,
        SEMANTIC_LIFECYCLE_REQUEST_CONTEXT_LABELS_V1,
        path,
    )
    if _require_positive_be64(fields[b"protocolVersion"], f"{path}.protocolVersion") != 1:
        raise VerificationError(f"{path}.protocolVersion must equal 1")
    actual_kind = _semantic_lifecycle_kind_from_tag(
        fields[b"requestKind"], f"{path}.requestKind"
    )
    if actual_kind != request_kind:
        raise VerificationError(f"{path}.requestKind must equal {request_kind!r}")
    for label in (
        b"requestId",
        b"accountId",
        b"walletId",
        b"sessionId",
        b"organizationId",
        b"projectId",
        b"environmentId",
        b"signingRootId",
        b"chainTarget",
        b"routerId",
        b"deriverSetId",
        b"deriverAId",
        b"deriverBId",
        b"signingWorkerId",
    ):
        _require_visible_ascii_bytes(fields[label], f"{path}.{label.decode('ascii')}")
    for label in (
        b"signingRootVersion",
        b"rootShareEpoch",
        b"deriverAKeyEpoch",
        b"deriverBKeyEpoch",
        b"signingWorkerKeyEpoch",
        b"requestExpiry",
    ):
        _require_positive_be64(fields[label], f"{path}.{label.decode('ascii')}")
    _require_fixed_bytes(fields[b"replayNonce"], 32, f"{path}.replayNonce")
    _require_fixed_bytes(
        fields[b"clientEphemeralPublicKey"],
        32,
        f"{path}.clientEphemeralPublicKey",
    )
    _, _, recipient_tag, _, output_tag, _ = CEREMONY_KIND_METADATA_V1[request_kind]
    if fields[b"recipientPlan"] != bytes((recipient_tag,)):
        raise VerificationError(f"{path}.recipientPlan has the wrong tag")
    if fields[b"outputPackageKind"] != bytes((output_tag,)):
        raise VerificationError(f"{path}.outputPackageKind has the wrong tag")
    return fields


def _parse_semantic_authorization_encoding(
    encoded: bytes,
    request_kind: str,
    request_context_digest: bytes,
    path: str,
) -> dict[bytes, bytes]:
    fields = _parse_labeled_lp32_encoding(
        encoded,
        CEREMONY_AUTHORIZATION_DOMAINS_V1[request_kind],
        SEMANTIC_LIFECYCLE_AUTHORIZATION_LABELS_V1[request_kind],
        path,
    )
    actual_kind = _semantic_lifecycle_kind_from_tag(
        fields[b"requestKind"], f"{path}.requestKind"
    )
    if actual_kind != request_kind:
        raise VerificationError(f"{path}.requestKind must equal {request_kind!r}")
    if fields[b"publicRequestContextDigest"] != request_context_digest:
        raise VerificationError(
            f"{path}.publicRequestContextDigest does not bind the request context"
        )
    _require_nonzero_bytes(
        fields[b"authorizationRecordDigest"],
        32,
        f"{path}.authorizationRecordDigest",
    )
    if request_kind == "registration":
        _require_nonzero_bytes(
            fields[b"registrationIntentDigest"],
            32,
            f"{path}.registrationIntentDigest",
        )
    elif request_kind == "activation":
        origin_kind = _semantic_lifecycle_kind_from_tag(
            fields[b"originRequestKind"], f"{path}.originRequestKind"
        )
        if origin_kind not in SEMANTIC_LIFECYCLE_ACTIVATION_ORIGINS_V1:
            raise VerificationError(f"{path}.originRequestKind is not activation-eligible")
        _require_nonzero_bytes(
            fields[b"originRequestContextDigest"],
            32,
            f"{path}.originRequestContextDigest",
        )
        _require_nonzero_bytes(
            fields[b"originTranscriptDigest"],
            32,
            f"{path}.originTranscriptDigest",
        )
        _require_nonzero_bytes(
            fields[b"packageSetDigest"], 32, f"{path}.packageSetDigest"
        )
        _require_positive_be64(fields[b"activationEpoch"], f"{path}.activationEpoch")
    elif request_kind == "recovery":
        _require_nonzero_bytes(
            fields[b"replacementCredentialBindingDigest"],
            32,
            f"{path}.replacementCredentialBindingDigest",
        )
    elif request_kind == "refresh":
        current_a = _require_positive_be64(
            fields[b"currentDeriverAInputStateEpoch"],
            f"{path}.currentDeriverAInputStateEpoch",
        )
        next_a = _require_positive_be64(
            fields[b"nextDeriverAInputStateEpoch"],
            f"{path}.nextDeriverAInputStateEpoch",
        )
        current_b = _require_positive_be64(
            fields[b"currentDeriverBInputStateEpoch"],
            f"{path}.currentDeriverBInputStateEpoch",
        )
        next_b = _require_positive_be64(
            fields[b"nextDeriverBInputStateEpoch"],
            f"{path}.nextDeriverBInputStateEpoch",
        )
        if next_a <= current_a or next_b <= current_b:
            raise VerificationError(f"{path} role input-state epochs must advance")
    else:
        registered_public_key = _require_fixed_bytes(
            fields[b"registeredEd25519PublicKey"],
            32,
            f"{path}.registeredEd25519PublicKey",
        )
        _verify_registered_public_key(
            registered_public_key, f"{path}.registeredEd25519PublicKey"
        )
    return fields


def _parse_semantic_transcript_encoding(
    encoded: bytes,
    request_kind: str,
    request_context_digest: bytes,
    authorization_digest: bytes,
    path: str,
) -> dict[bytes, bytes]:
    fields = _parse_labeled_lp32_encoding(
        encoded,
        CEREMONY_TRANSCRIPT_ENCODING_DOMAIN_V1,
        SEMANTIC_LIFECYCLE_TRANSCRIPT_LABELS_V1,
        path,
    )
    if _require_positive_be64(fields[b"protocolVersion"], f"{path}.protocolVersion") != 1:
        raise VerificationError(f"{path}.protocolVersion must equal 1")
    if fields[b"protocolId"] != PROTOCOL_ID_V1.encode("ascii"):
        raise VerificationError(f"{path}.protocolId has the wrong protocol")
    actual_kind = _semantic_lifecycle_kind_from_tag(
        fields[b"requestKind"], f"{path}.requestKind"
    )
    if actual_kind != request_kind:
        raise VerificationError(f"{path}.requestKind must equal {request_kind!r}")
    if fields[b"circuitId"] != CEREMONY_KIND_METADATA_V1[request_kind][5].encode(
        "ascii"
    ):
        raise VerificationError(f"{path}.circuitId has the wrong circuit")
    if fields[b"publicRequestContextDigest"] != request_context_digest:
        raise VerificationError(
            f"{path}.publicRequestContextDigest does not bind the request context"
        )
    if fields[b"authorizationDigest"] != authorization_digest:
        raise VerificationError(
            f"{path}.authorizationDigest does not bind the authorization"
        )
    _require_fixed_bytes(fields[b"transcriptNonce"], 32, f"{path}.transcriptNonce")
    _require_nonzero_bytes(
        fields[b"transportBindingDigest"],
        32,
        f"{path}.transportBindingDigest",
    )
    _require_nonzero_bytes(
        fields[b"artifactSuiteDigest"], 32, f"{path}.artifactSuiteDigest"
    )
    return fields


def _verify_semantic_ceremony_vector(
    value: Any, request_kind: str, path: str
) -> dict[str, Any]:
    vector = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_CEREMONY_KEY_ORDER, path
    )
    request_encoding = _decode_variable_hex(
        vector["public_request_context_encoding_hex"],
        f"{path}.public_request_context_encoding_hex",
    )
    request_digest = hashlib.sha256(request_encoding).digest()
    _require_expected_bytes(
        vector["public_request_context_digest_sha256_hex"],
        request_digest,
        f"{path}.public_request_context_digest_sha256_hex",
    )
    request_fields = _parse_semantic_request_context_encoding(
        request_encoding, request_kind, f"{path}.public_request_context"
    )

    authorization_encoding = _decode_variable_hex(
        vector["authorization_encoding_hex"], f"{path}.authorization_encoding_hex"
    )
    authorization_digest = hashlib.sha256(authorization_encoding).digest()
    _require_expected_bytes(
        vector["authorization_digest_sha256_hex"],
        authorization_digest,
        f"{path}.authorization_digest_sha256_hex",
    )
    authorization_fields = _parse_semantic_authorization_encoding(
        authorization_encoding,
        request_kind,
        request_digest,
        f"{path}.authorization",
    )

    transcript_encoding = _decode_variable_hex(
        vector["transcript_encoding_hex"], f"{path}.transcript_encoding_hex"
    )
    transcript_digest = hashlib.sha256(transcript_encoding).digest()
    _require_expected_bytes(
        vector["transcript_digest_sha256_hex"],
        transcript_digest,
        f"{path}.transcript_digest_sha256_hex",
    )
    transcript_fields = _parse_semantic_transcript_encoding(
        transcript_encoding,
        request_kind,
        request_digest,
        authorization_digest,
        f"{path}.transcript",
    )
    return {
        "request_encoding": request_encoding,
        "request_digest": request_digest,
        "request_fields": request_fields,
        "authorization_encoding": authorization_encoding,
        "authorization_digest": authorization_digest,
        "authorization_fields": authorization_fields,
        "transcript_encoding": transcript_encoding,
        "transcript_digest": transcript_digest,
        "transcript_fields": transcript_fields,
    }


def _verified_ceremony_digest_map(
    corpus: Any,
) -> dict[str, tuple[bytes, bytes, bytes]]:
    """Rebuilds the fixed public ceremony DAG and returns its digest bindings."""
    corpus_object = _require_ordered_keys(
        corpus, CEREMONY_CONTEXT_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(corpus_object["schema"], "$.schema"),
        CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(corpus_object["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(corpus_object["evidence_scope"], "$.evidence_scope"),
        CEREMONY_CONTEXT_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) != len(CEREMONY_CASE_SEQUENCE_V1):
        raise VerificationError("$.cases must contain exactly five ceremony cases")

    registration_origin: tuple[bytes, bytes] | None = None
    digest_map: dict[str, tuple[bytes, bytes, bytes]] = {}
    for index, (expected_kind, expected_case_id, _) in enumerate(
        CEREMONY_CASE_SEQUENCE_V1
    ):
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], CEREMONY_CONTEXT_CASE_KEY_ORDER, case_path
        )
        request_kind = _require_string(
            case["request_kind"], f"{case_path}.request_kind"
        )
        if request_kind != expected_kind:
            raise VerificationError(
                f"{case_path}.request_kind must equal {expected_kind!r}"
            )
        vector_path = f"{case_path}.vector"
        vector = _require_ordered_keys(
            case["vector"], CEREMONY_CONTEXT_VECTOR_KEY_ORDER, vector_path
        )
        _require_exact_value(
            _require_string(vector["case_id"], f"{vector_path}.case_id"),
            expected_case_id,
            f"{vector_path}.case_id",
        )
        expected = _require_ordered_keys(
            vector["expected"], CEREMONY_EXPECTED_KEY_ORDER, f"{vector_path}.expected"
        )
        request_digest = _verify_ceremony_request_context(
            vector["public_request_context"],
            expected,
            request_kind,
            f"{vector_path}.public_request_context",
        )
        authorization_digest = _verify_ceremony_authorization(
            vector["authorization"],
            expected,
            request_kind,
            request_digest,
            registration_origin,
            f"{vector_path}.authorization",
        )
        transcript_digest = _verify_ceremony_transcript(
            vector["transcript"],
            expected,
            request_kind,
            request_digest,
            authorization_digest,
            f"{vector_path}.transcript",
        )
        if request_kind == "registration":
            registration_origin = (request_digest, transcript_digest)
        digest_map[request_kind] = (
            request_digest,
            transcript_digest,
            authorization_digest,
        )
    return digest_map


def verify_ceremony_context_corpus(corpus: Any) -> int:
    """Independently rebuilds the fixed public ceremony DAG and all digests."""
    return len(_verified_ceremony_digest_map(corpus))


def verify_provenance_ceremony_links(
    ceremony_context_corpus: Any, provenance_corpus: Any
) -> int:
    """Ties every provenance ceremony tuple to independently rebuilt DAG bytes."""
    ceremony_digests = _verified_ceremony_digest_map(ceremony_context_corpus)
    case_count = _verify_provenance_outer_corpus(provenance_corpus)
    provenance = _require_ordered_keys(
        provenance_corpus, PROVENANCE_CORPUS_KEY_ORDER, "$"
    )
    cases = provenance["cases"]
    for index, (request_kind, _, _) in enumerate(PROVENANCE_CASE_SEQUENCE_V1):
        vector_path = f"$.cases[{index}].vector"
        vector = _require_ordered_keys(
            cases[index]["vector"], PROVENANCE_VECTOR_KEY_ORDER, vector_path
        )
        actual = (
            _decode_hex(
                vector["public_request_context_digest_hex"],
                32,
                f"{vector_path}.public_request_context_digest_hex",
            ),
            _decode_hex(
                vector["transcript_digest_hex"],
                32,
                f"{vector_path}.transcript_digest_hex",
            ),
            _decode_hex(
                vector["authorization_digest_hex"],
                32,
                f"{vector_path}.authorization_digest_hex",
            ),
        )
        expected = ceremony_digests.get(request_kind)
        if expected is None:
            raise VerificationError(
                f"{vector_path} has no independently reconstructed ceremony DAG"
            )
        if actual != expected:
            raise VerificationError(
                f"{vector_path} ceremony digests do not match the independently reconstructed DAG"
            )
    return case_count


def verify_provenance_corpus(
    corpus: Any, ceremony_context_corpus: Any
) -> int:
    """Verifies provenance bytes and their independently rebuilt ceremony DAGs."""
    return verify_provenance_ceremony_links(ceremony_context_corpus, corpus)


def _verified_ceremony_encoding_map(corpus: Any) -> dict[str, dict[str, bytes]]:
    _verified_ceremony_digest_map(corpus)
    cases = _require_object(corpus, "$")["cases"]
    encoding_map: dict[str, dict[str, bytes]] = {}
    for index, (request_kind, _, _) in enumerate(CEREMONY_CASE_SEQUENCE_V1):
        expected = cases[index]["vector"]["expected"]
        encoding_map[request_kind] = {
            "request_encoding": _decode_variable_hex(
                expected["public_request_context_encoding_hex"],
                f"$.cases[{index}].vector.expected.public_request_context_encoding_hex",
            ),
            "request_digest": _decode_hex(
                expected["public_request_context_digest_sha256_hex"],
                32,
                f"$.cases[{index}].vector.expected.public_request_context_digest_sha256_hex",
            ),
            "authorization_encoding": _decode_variable_hex(
                expected["authorization_encoding_hex"],
                f"$.cases[{index}].vector.expected.authorization_encoding_hex",
            ),
            "authorization_digest": _decode_hex(
                expected["authorization_digest_sha256_hex"],
                32,
                f"$.cases[{index}].vector.expected.authorization_digest_sha256_hex",
            ),
            "transcript_encoding": _decode_variable_hex(
                expected["transcript_encoding_hex"],
                f"$.cases[{index}].vector.expected.transcript_encoding_hex",
            ),
            "transcript_digest": _decode_hex(
                expected["transcript_digest_sha256_hex"],
                32,
                f"$.cases[{index}].vector.expected.transcript_digest_sha256_hex",
            ),
        }
    return encoding_map


def _provenance_registered_public_key(
    role_vector: dict[str, Any], request_kind: str, path: str
) -> bytes | None:
    if request_kind == "registration":
        return None
    encoded = _decode_variable_hex(
        role_vector["branch_encoding_hex"], f"{path}.branch_encoding_hex"
    )
    if request_kind == "recovery":
        fields = _parse_lp32_fields(encoded, 4, f"{path}.branch_encoding_hex")
        expected_domain = PROVENANCE_RECOVERY_BRANCH_ENCODING_DOMAIN_V1
        key = fields[2]
    elif request_kind == "refresh":
        fields = _parse_lp32_fields(encoded, 5, f"{path}.branch_encoding_hex")
        expected_domain = PROVENANCE_REFRESH_BRANCH_ENCODING_DOMAIN_V1
        key = fields[3]
    elif request_kind == "export":
        fields = _parse_lp32_fields(encoded, 3, f"{path}.branch_encoding_hex")
        expected_domain = PROVENANCE_EXPORT_BRANCH_ENCODING_DOMAIN_V1
        key = fields[2]
    else:
        raise VerificationError(f"{path} has unsupported provenance request kind")
    if fields[0] != expected_domain:
        raise VerificationError(f"{path}.branch_encoding_hex has the wrong domain")
    _require_fixed_bytes(key, 32, f"{path}.registered_public_key")
    _verify_registered_public_key(key, f"{path}.registered_public_key")
    return key


def _verified_provenance_semantic_map(
    provenance_corpus: Any, ceremony_context_corpus: Any
) -> dict[str, dict[str, Any]]:
    verify_provenance_corpus(provenance_corpus, ceremony_context_corpus)
    cases = _require_object(provenance_corpus, "$")["cases"]
    semantic_map: dict[str, dict[str, Any]] = {}
    for index, (request_kind, _, _) in enumerate(PROVENANCE_CASE_SEQUENCE_V1):
        vector = cases[index]["vector"]
        a_key = _provenance_registered_public_key(
            vector["deriver_a"], request_kind, f"$.cases[{index}].vector.deriver_a"
        )
        b_key = _provenance_registered_public_key(
            vector["deriver_b"], request_kind, f"$.cases[{index}].vector.deriver_b"
        )
        if a_key != b_key:
            raise VerificationError(
                f"$.cases[{index}] provenance roles disagree on the registered key"
            )
        semantic_map[request_kind] = {
            "pair_digest": _decode_hex(
                vector["pair_digest_sha256_hex"],
                32,
                f"$.cases[{index}].vector.pair_digest_sha256_hex",
            ),
            "registered_public_key": a_key,
        }
    return semantic_map


def _semantic_ceremony_binding_from_fields(
    fields: Sequence[bytes], start: int, path: str
) -> dict[str, bytes]:
    names = (
        "request_digest",
        "authorization_digest",
        "transcript_digest",
        "transport_digest",
        "artifact_digest",
        "one_use_execution_id",
        "input_provenance_digest",
        "evaluation_evidence_digest",
    )
    binding: dict[str, bytes] = {}
    for offset, name in enumerate(names):
        binding[name] = _require_nonzero_bytes(
            fields[start + offset], 32, f"{path}.{name}"
        )
    return binding


def _require_semantic_ceremony_binding(
    binding: dict[str, bytes],
    ceremony: dict[str, Any],
    provenance_digest: bytes,
    path: str,
) -> None:
    expected = {
        "request_digest": ceremony["request_digest"],
        "authorization_digest": ceremony["authorization_digest"],
        "transcript_digest": ceremony["transcript_digest"],
        "transport_digest": ceremony["transcript_fields"][b"transportBindingDigest"],
        "artifact_digest": ceremony["transcript_fields"][b"artifactSuiteDigest"],
        "input_provenance_digest": provenance_digest,
    }
    for name, expected_value in expected.items():
        if binding[name] != expected_value:
            raise VerificationError(f"{path}.{name} does not match its bound source")


def _verify_activation_descriptor(
    encoded_value: Any,
    domain: bytes,
    request_kind: str,
    role_tag: int,
    recipient_tag: int,
    output_tag: int,
    recipient_binding_domain: bytes,
    ceremony: dict[str, Any],
    provenance_digest: bytes,
    path: str,
) -> dict[str, Any]:
    encoded = _decode_variable_hex(encoded_value, path)
    fields = _parse_lp32_fields(encoded, 21, path)
    if fields[0] != domain:
        raise VerificationError(f"{path} has the wrong descriptor domain")
    expected_tags = (
        bytes((CEREMONY_KIND_METADATA_V1[request_kind][0],)),
        bytes((role_tag,)),
        bytes((recipient_tag,)),
        bytes((output_tag,)),
    )
    for offset, expected_tag in enumerate(expected_tags, start=1):
        if fields[offset] != expected_tag:
            raise VerificationError(f"{path} has an invalid descriptor tag at field {offset}")
    binding = _semantic_ceremony_binding_from_fields(fields, 5, path)
    _require_semantic_ceremony_binding(binding, ceremony, provenance_digest, path)
    activation_epoch = _require_positive_be64(fields[13], f"{path}.activation_epoch")
    expected_recipient_binding = _digest_encoding(
        recipient_binding_domain, ceremony["request_digest"]
    )
    if fields[14] != expected_recipient_binding:
        raise VerificationError(f"{path}.recipient_binding is not independently derived")
    scalar_share_point = _require_fixed_bytes(
        fields[15], 32, f"{path}.scalar_share_point"
    )
    _require_prime_order_subgroup_point(
        scalar_share_point, f"{path}.scalar_share_point"
    )
    for index, name in (
        (16, "recipient_protection_digest"),
        (17, "recipient_ciphertext_digest"),
        (19, "output_binding_digest"),
        (20, "package_authentication_digest"),
    ):
        _require_nonzero_bytes(fields[index], 32, f"{path}.{name}")
    _require_positive_be64(fields[18], f"{path}.ciphertext_length")
    return {
        "encoding": encoded,
        "binding": binding,
        "activation_epoch": activation_epoch,
        "scalar_share_point": scalar_share_point,
        "recipient_key_binding": fields[14],
        "recipient_protection_digest": fields[16],
        "recipient_ciphertext_digest": fields[17],
        "ciphertext_length": int.from_bytes(fields[18], "big"),
        "output_binding_digest": fields[19],
        "package_authentication_digest": fields[20],
    }


def _verify_activation_package_set(
    value: Any,
    request_kind: str,
    ceremony: dict[str, Any],
    provenance_digest: bytes,
    path: str,
) -> dict[str, Any]:
    packages = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_ACTIVATION_PACKAGES_KEY_ORDER, path
    )
    descriptors = (
        _verify_activation_descriptor(
            packages["deriver_a_client_descriptor_encoding_hex"],
            ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1,
            request_kind,
            1,
            1,
            1,
            CLIENT_RECIPIENT_KEY_BINDING_DOMAIN_V1,
            ceremony,
            provenance_digest,
            f"{path}.deriver_a_client_descriptor_encoding_hex",
        ),
        _verify_activation_descriptor(
            packages["deriver_b_client_descriptor_encoding_hex"],
            ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
            request_kind,
            2,
            1,
            1,
            CLIENT_RECIPIENT_KEY_BINDING_DOMAIN_V1,
            ceremony,
            provenance_digest,
            f"{path}.deriver_b_client_descriptor_encoding_hex",
        ),
        _verify_activation_descriptor(
            packages["deriver_a_signing_worker_descriptor_encoding_hex"],
            ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
            request_kind,
            1,
            2,
            2,
            SIGNING_WORKER_RECIPIENT_KEY_BINDING_DOMAIN_V1,
            ceremony,
            provenance_digest,
            f"{path}.deriver_a_signing_worker_descriptor_encoding_hex",
        ),
        _verify_activation_descriptor(
            packages["deriver_b_signing_worker_descriptor_encoding_hex"],
            ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
            request_kind,
            2,
            2,
            2,
            SIGNING_WORKER_RECIPIENT_KEY_BINDING_DOMAIN_V1,
            ceremony,
            provenance_digest,
            f"{path}.deriver_b_signing_worker_descriptor_encoding_hex",
        ),
    )
    baseline = descriptors[0]
    for index, descriptor in enumerate(descriptors[1:], start=1):
        if descriptor["activation_epoch"] != baseline["activation_epoch"]:
            raise VerificationError(f"{path} descriptor {index} has another activation epoch")
        for name in (
            "one_use_execution_id",
            "input_provenance_digest",
            "evaluation_evidence_digest",
        ):
            if descriptor["binding"][name] != baseline["binding"][name]:
                raise VerificationError(f"{path} descriptor {index} has another {name}")
    expected_encoding = _lp32_join(
        (ACTIVATION_PACKAGE_SET_ENCODING_DOMAIN_V1,)
        + tuple(descriptor["encoding"] for descriptor in descriptors)
    )
    _require_expected_bytes(
        packages["package_set_encoding_hex"],
        expected_encoding,
        f"{path}.package_set_encoding_hex",
    )
    package_digest = _digest_encoding(
        ACTIVATION_PACKAGE_SET_DIGEST_DOMAIN_V1, expected_encoding
    )
    _require_expected_bytes(
        packages["package_set_digest_sha256_hex"],
        package_digest,
        f"{path}.package_set_digest_sha256_hex",
    )
    return {
        "descriptors": descriptors,
        "package_set_encoding": expected_encoding,
        "package_set_digest": package_digest,
        "activation_epoch": baseline["activation_epoch"],
        "binding": baseline["binding"],
    }


def _verify_activation_receipt(
    value: Any,
    request_kind: str,
    ceremony: dict[str, Any],
    provenance_digest: bytes,
    packages: dict[str, Any],
    expected_registered_public_key: bytes | None,
    path: str,
) -> dict[str, Any]:
    receipt = _require_ordered_keys(value, SEMANTIC_LIFECYCLE_RECEIPT_KEY_ORDER, path)
    encoded = _decode_variable_hex(
        receipt["receipt_body_encoding_hex"], f"{path}.receipt_body_encoding_hex"
    )
    fields = _parse_lp32_fields(encoded, 19, f"{path}.receipt_body_encoding_hex")
    if fields[0] != ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1:
        raise VerificationError(f"{path} has the wrong receipt domain")
    if fields[1] != b"\x01" or fields[2] != b"\x01":
        raise VerificationError(f"{path} has invalid activation receipt/status tags")
    if fields[3] != bytes((CEREMONY_KIND_METADATA_V1[request_kind][0],)):
        raise VerificationError(f"{path} has the wrong request-kind tag")
    binding = _semantic_ceremony_binding_from_fields(fields, 4, path)
    _require_semantic_ceremony_binding(binding, ceremony, provenance_digest, path)
    for name in ("one_use_execution_id", "evaluation_evidence_digest"):
        if binding[name] != packages["binding"][name]:
            raise VerificationError(f"{path}.{name} disagrees with the packages")
    activation_epoch = _require_positive_be64(fields[12], f"{path}.activation_epoch")
    if activation_epoch != packages["activation_epoch"]:
        raise VerificationError(f"{path}.activation_epoch disagrees with the packages")
    if fields[13] != packages["package_set_digest"]:
        raise VerificationError(f"{path}.package_set_digest disagrees with the packages")
    x_client = _require_fixed_bytes(fields[14], 32, f"{path}.x_client")
    x_server = _require_fixed_bytes(fields[15], 32, f"{path}.x_server")
    registered_public_key = _require_fixed_bytes(
        fields[16], 32, f"{path}.registered_public_key"
    )
    _require_nonzero_bytes(fields[17], 32, f"{path}.deriver_a_receipt_evidence")
    _require_nonzero_bytes(fields[18], 32, f"{path}.deriver_b_receipt_evidence")
    descriptors = packages["descriptors"]
    _require_point_addition(
        descriptors[0]["scalar_share_point"],
        descriptors[1]["scalar_share_point"],
        x_client,
        f"{path}.client_point_addition",
    )
    _require_point_addition(
        descriptors[2]["scalar_share_point"],
        descriptors[3]["scalar_share_point"],
        x_server,
        f"{path}.signing_worker_point_addition",
    )
    _require_activation_public_relation(
        x_client, x_server, registered_public_key, f"{path}.public_relation"
    )
    if (
        expected_registered_public_key is not None
        and registered_public_key != expected_registered_public_key
    ):
        raise VerificationError(f"{path}.registered_public_key is not provenance-bound")
    receipt_digest = _digest_encoding(
        ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1, encoded
    )
    _require_expected_bytes(
        receipt["receipt_body_digest_sha256_hex"],
        receipt_digest,
        f"{path}.receipt_body_digest_sha256_hex",
    )
    return {
        "encoding": encoded,
        "receipt_digest": receipt_digest,
        "activation_epoch": activation_epoch,
        "x_client": x_client,
        "x_server": x_server,
        "registered_public_key": registered_public_key,
        "deriver_a_receipt_evidence_digest": fields[17],
        "deriver_b_receipt_evidence_digest": fields[18],
        "binding": binding,
    }


def _verify_export_descriptor(
    encoded_value: Any,
    domain: bytes,
    role_tag: int,
    ceremony: dict[str, Any],
    provenance_digest: bytes,
    path: str,
) -> dict[str, Any]:
    encoded = _decode_variable_hex(encoded_value, path)
    fields = _parse_lp32_fields(encoded, 19, path)
    if fields[0] != domain:
        raise VerificationError(f"{path} has the wrong descriptor domain")
    expected_tags = (b"\x05", bytes((role_tag,)), b"\x01", b"\x03")
    for offset, expected_tag in enumerate(expected_tags, start=1):
        if fields[offset] != expected_tag:
            raise VerificationError(f"{path} has an invalid descriptor tag at field {offset}")
    binding = _semantic_ceremony_binding_from_fields(fields, 5, path)
    _require_semantic_ceremony_binding(binding, ceremony, provenance_digest, path)
    expected_recipient_binding = _digest_encoding(
        CLIENT_RECIPIENT_KEY_BINDING_DOMAIN_V1, ceremony["request_digest"]
    )
    if fields[13] != expected_recipient_binding:
        raise VerificationError(f"{path}.recipient_binding is not independently derived")
    for index, name in (
        (14, "recipient_protection_digest"),
        (15, "recipient_ciphertext_digest"),
        (17, "output_binding_digest"),
        (18, "package_authentication_digest"),
    ):
        _require_nonzero_bytes(fields[index], 32, f"{path}.{name}")
    _require_positive_be64(fields[16], f"{path}.ciphertext_length")
    return {
        "encoding": encoded,
        "binding": binding,
        "recipient_key_binding": fields[13],
        "recipient_protection_digest": fields[14],
        "recipient_ciphertext_digest": fields[15],
        "ciphertext_length": int.from_bytes(fields[16], "big"),
        "output_binding_digest": fields[17],
        "package_authentication_digest": fields[18],
    }


def _verify_export_package_set(
    value: Any,
    ceremony: dict[str, Any],
    provenance_digest: bytes,
    path: str,
) -> dict[str, Any]:
    packages = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_EXPORT_PACKAGES_KEY_ORDER, path
    )
    descriptors = (
        _verify_export_descriptor(
            packages["deriver_a_client_descriptor_encoding_hex"],
            EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1,
            1,
            ceremony,
            provenance_digest,
            f"{path}.deriver_a_client_descriptor_encoding_hex",
        ),
        _verify_export_descriptor(
            packages["deriver_b_client_descriptor_encoding_hex"],
            EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
            2,
            ceremony,
            provenance_digest,
            f"{path}.deriver_b_client_descriptor_encoding_hex",
        ),
    )
    for name in (
        "one_use_execution_id",
        "input_provenance_digest",
        "evaluation_evidence_digest",
    ):
        if descriptors[0]["binding"][name] != descriptors[1]["binding"][name]:
            raise VerificationError(f"{path} descriptors disagree on {name}")
    expected_encoding = _lp32_join(
        (
            EXPORT_PACKAGE_SET_ENCODING_DOMAIN_V1,
            descriptors[0]["encoding"],
            descriptors[1]["encoding"],
        )
    )
    _require_expected_bytes(
        packages["package_set_encoding_hex"],
        expected_encoding,
        f"{path}.package_set_encoding_hex",
    )
    package_digest = _digest_encoding(EXPORT_PACKAGE_SET_DIGEST_DOMAIN_V1, expected_encoding)
    _require_expected_bytes(
        packages["package_set_digest_sha256_hex"],
        package_digest,
        f"{path}.package_set_digest_sha256_hex",
    )
    return {
        "descriptors": descriptors,
        "package_set_encoding": expected_encoding,
        "package_set_digest": package_digest,
        "binding": descriptors[0]["binding"],
    }


def _verify_export_receipt(
    value: Any,
    ceremony: dict[str, Any],
    provenance_digest: bytes,
    packages: dict[str, Any],
    expected_registered_public_key: bytes,
    path: str,
) -> dict[str, Any]:
    receipt = _require_ordered_keys(value, SEMANTIC_LIFECYCLE_RECEIPT_KEY_ORDER, path)
    encoded = _decode_variable_hex(
        receipt["receipt_body_encoding_hex"], f"{path}.receipt_body_encoding_hex"
    )
    fields = _parse_lp32_fields(encoded, 17, f"{path}.receipt_body_encoding_hex")
    if fields[0] != EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1:
        raise VerificationError(f"{path} has the wrong receipt domain")
    if fields[1] != b"\x02" or fields[2] != b"\x02" or fields[3] != b"\x05":
        raise VerificationError(f"{path} has invalid export receipt/status tags")
    binding = _semantic_ceremony_binding_from_fields(fields, 4, path)
    _require_semantic_ceremony_binding(binding, ceremony, provenance_digest, path)
    for name in ("one_use_execution_id", "evaluation_evidence_digest"):
        if binding[name] != packages["binding"][name]:
            raise VerificationError(f"{path}.{name} disagrees with the packages")
    if fields[12] != packages["package_set_digest"]:
        raise VerificationError(f"{path}.package_set_digest disagrees with the packages")
    registered_public_key = _require_fixed_bytes(
        fields[13], 32, f"{path}.registered_public_key"
    )
    _verify_registered_public_key(registered_public_key, f"{path}.registered_public_key")
    if registered_public_key != expected_registered_public_key:
        raise VerificationError(f"{path}.registered_public_key is not provenance-bound")
    authorization_key = ceremony["authorization_fields"][b"registeredEd25519PublicKey"]
    if registered_public_key != authorization_key:
        raise VerificationError(f"{path}.registered_public_key is not authorization-bound")
    for index, name in (
        (14, "output_committed_receipt_digest"),
        (15, "client_delivery_evidence_digest"),
        (16, "consumed_authorization_digest"),
    ):
        _require_nonzero_bytes(fields[index], 32, f"{path}.{name}")
    receipt_digest = _digest_encoding(EXPORT_RELEASED_RECEIPT_DIGEST_DOMAIN_V1, encoded)
    _require_expected_bytes(
        receipt["receipt_body_digest_sha256_hex"],
        receipt_digest,
        f"{path}.receipt_body_digest_sha256_hex",
    )
    return {
        "encoding": encoded,
        "receipt_digest": receipt_digest,
        "registered_public_key": registered_public_key,
        "output_committed_receipt_digest": fields[14],
        "client_delivery_evidence_digest": fields[15],
        "export_authorization_consumption_evidence_digest": fields[16],
        "binding": binding,
    }


def _verify_semantic_lifecycle_case_id(
    value: Any, seen: set[str], path: str
) -> str:
    case_id = _require_string(value, path)
    try:
        encoded = case_id.encode("ascii")
    except UnicodeEncodeError as error:
        raise VerificationError(f"{path} must contain visible ASCII") from error
    _require_visible_ascii_bytes(encoded, path)
    if case_id in seen:
        raise VerificationError(f"{path} duplicates another semantic lifecycle case id")
    seen.add(case_id)
    return case_id


def _verify_output_committed_projection(
    value: Any,
    expected: dict[str, Any] | None,
    path: str,
) -> dict[str, Any]:
    projection = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_OUTPUT_COMMITTED_KEY_ORDER, path
    )
    identity_path = f"{path}.identity"
    identity = _require_ordered_keys(
        projection["identity"], SEMANTIC_LIFECYCLE_ARTIFACT_IDENTITY_KEY_ORDER, identity_path
    )
    origin_kind = _require_string(identity["origin_kind"], f"{identity_path}.origin_kind")
    if origin_kind not in SEMANTIC_LIFECYCLE_ACTIVATION_ORIGINS_V1:
        raise VerificationError(f"{identity_path}.origin_kind is not activation-eligible")
    origin_request_kind = _require_string(
        identity["origin_request_kind"], f"{identity_path}.origin_request_kind"
    )
    if origin_request_kind != origin_kind:
        raise VerificationError(
            f"{identity_path}.origin_request_kind must equal the origin kind"
        )
    normalized = {
        "origin_kind": origin_kind,
        "origin_request_kind": origin_request_kind,
        "origin_request_context_digest": _ceremony_nonzero_digest(
            identity["origin_request_context_digest_hex"],
            f"{identity_path}.origin_request_context_digest_hex",
        ),
        "origin_authorization_digest": _ceremony_nonzero_digest(
            identity["origin_authorization_digest_hex"],
            f"{identity_path}.origin_authorization_digest_hex",
        ),
        "origin_transcript_digest": _ceremony_nonzero_digest(
            identity["origin_transcript_digest_hex"],
            f"{identity_path}.origin_transcript_digest_hex",
        ),
        "one_use_execution_id": _ceremony_nonzero_digest(
            identity["one_use_execution_id_hex"],
            f"{identity_path}.one_use_execution_id_hex",
        ),
        "package_set_digest": _ceremony_nonzero_digest(
            identity["package_set_digest_hex"],
            f"{identity_path}.package_set_digest_hex",
        ),
        "receipt_digest": _ceremony_nonzero_digest(
            identity["receipt_digest_hex"], f"{identity_path}.receipt_digest_hex"
        ),
        "activation_epoch": _require_epoch(
            identity["activation_epoch"], f"{identity_path}.activation_epoch"
        ),
        "registered_public_key": _decode_hex(
            identity["registered_public_key_hex"],
            32,
            f"{identity_path}.registered_public_key_hex",
        ),
    }
    _verify_registered_public_key(
        normalized["registered_public_key"], f"{identity_path}.registered_public_key_hex"
    )
    if expected is not None and normalized != expected:
        raise VerificationError(f"{identity_path} does not match the committed artifacts")
    return normalized


def _verify_output_committed_persistence(
    value: Any, expected: dict[str, Any], path: str
) -> dict[str, Any]:
    persistence = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_PERSISTENCE_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(persistence["state"], f"{path}.state"),
        "output_committed",
        f"{path}.state",
    )
    return _verify_output_committed_projection(
        persistence["projection"], expected, f"{path}.projection"
    )


def _verify_metadata_consumed_persistence(
    value: Any,
    expected_committed: dict[str, Any],
    activation_ceremony: dict[str, Any],
    path: str,
) -> dict[str, Any]:
    persistence = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_PERSISTENCE_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(persistence["state"], f"{path}.state"),
        "metadata_consumed",
        f"{path}.state",
    )
    projection_path = f"{path}.projection"
    projection = _require_ordered_keys(
        persistence["projection"],
        SEMANTIC_LIFECYCLE_METADATA_PROJECTION_KEY_ORDER,
        projection_path,
    )
    committed = _verify_output_committed_projection(
        projection["committed"], expected_committed, f"{projection_path}.committed"
    )
    for field_name, ceremony_name in (
        ("activation_request_context_digest_hex", "request_digest"),
        ("activation_authorization_digest_hex", "authorization_digest"),
        ("activation_transcript_digest_hex", "transcript_digest"),
    ):
        actual = _ceremony_nonzero_digest(
            projection[field_name], f"{projection_path}.{field_name}"
        )
        if actual != activation_ceremony[ceremony_name]:
            raise VerificationError(
                f"{projection_path}.{field_name} does not match activation control"
            )
    return committed


def _verify_attempt_rejected_persistence(
    value: Any,
    expected_committed: dict[str, Any],
    path: str,
) -> dict[str, Any]:
    persistence = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_PERSISTENCE_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(persistence["state"], f"{path}.state"),
        "attempt_rejected",
        f"{path}.state",
    )
    projection_path = f"{path}.projection"
    projection = _require_ordered_keys(
        persistence["projection"],
        SEMANTIC_LIFECYCLE_ATTEMPT_REJECTED_KEY_ORDER,
        projection_path,
    )
    before = _verify_output_committed_projection(
        projection["before"], expected_committed, f"{projection_path}.before"
    )
    after = _verify_output_committed_projection(
        projection["after"], expected_committed, f"{projection_path}.after"
    )
    if before != after:
        raise VerificationError(f"{projection_path} is not an exact retry self-loop")
    abort_path = f"{projection_path}.abort"
    abort = _require_ordered_keys(
        projection["abort"], SEMANTIC_LIFECYCLE_ABORT_KEY_ORDER, abort_path
    )
    _require_exact_value(
        _require_string(abort["request_kind"], f"{abort_path}.request_kind"),
        "activation",
        f"{abort_path}.request_kind",
    )
    abort_transcript_digest = _ceremony_nonzero_digest(
        abort["public_transcript_digest_hex"],
        f"{abort_path}.public_transcript_digest_hex",
    )
    _require_exact_value(
        _require_string(
            abort["public_failure_code"], f"{abort_path}.public_failure_code"
        ),
        "rejected",
        f"{abort_path}.public_failure_code",
    )
    _require_exact_value(
        _require_string(abort["terminal"], f"{abort_path}.terminal"),
        "aborted",
        f"{abort_path}.terminal",
    )
    return {
        "committed": before,
        "abort_transcript_digest": abort_transcript_digest,
    }


def _require_semantic_ceremony_companion(
    ceremony: dict[str, Any], companion: dict[str, bytes], path: str
) -> None:
    for name in (
        "request_encoding",
        "request_digest",
        "authorization_encoding",
        "authorization_digest",
        "transcript_encoding",
        "transcript_digest",
    ):
        if ceremony[name] != companion[name]:
            raise VerificationError(f"{path}.{name} does not match the ceremony corpus")


def _verify_semantic_activation_artifact_case(
    value: Any,
    request_kind: str,
    ceremony_companion: dict[str, bytes],
    provenance: dict[str, Any],
    case_ids: set[str],
    path: str,
) -> dict[str, Any]:
    vector = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_ACTIVATION_ARTIFACT_CASE_KEY_ORDER, path
    )
    case_id = _verify_semantic_lifecycle_case_id(
        vector["case_id"], case_ids, f"{path}.case_id"
    )
    ceremony = _verify_semantic_ceremony_vector(
        vector["ceremony"], request_kind, f"{path}.ceremony"
    )
    _require_semantic_ceremony_companion(ceremony, ceremony_companion, f"{path}.ceremony")
    packages = _verify_activation_package_set(
        vector["packages"],
        request_kind,
        ceremony,
        provenance["pair_digest"],
        f"{path}.packages",
    )
    receipt = _verify_activation_receipt(
        vector["receipt"],
        request_kind,
        ceremony,
        provenance["pair_digest"],
        packages,
        provenance["registered_public_key"],
        f"{path}.receipt",
    )
    expected_identity = {
        "origin_kind": request_kind,
        "origin_request_kind": request_kind,
        "origin_request_context_digest": ceremony["request_digest"],
        "origin_authorization_digest": ceremony["authorization_digest"],
        "origin_transcript_digest": ceremony["transcript_digest"],
        "one_use_execution_id": packages["binding"]["one_use_execution_id"],
        "package_set_digest": packages["package_set_digest"],
        "receipt_digest": receipt["receipt_digest"],
        "activation_epoch": packages["activation_epoch"],
        "registered_public_key": receipt["registered_public_key"],
    }
    committed = _verify_output_committed_persistence(
        vector["persistence"], expected_identity, f"{path}.persistence"
    )
    return {
        "case_id": case_id,
        "request_kind": request_kind,
        "ceremony": ceremony,
        "packages": packages,
        "receipt": receipt,
        "committed": committed,
    }


def _verify_semantic_export_artifact_case(
    value: Any,
    ceremony_companion: dict[str, bytes],
    provenance: dict[str, Any],
    case_ids: set[str],
    path: str,
) -> dict[str, Any]:
    vector = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_EXPORT_CASE_KEY_ORDER, path
    )
    case_id = _verify_semantic_lifecycle_case_id(
        vector["case_id"], case_ids, f"{path}.case_id"
    )
    ceremony = _verify_semantic_ceremony_vector(
        vector["ceremony"], "export", f"{path}.ceremony"
    )
    _require_semantic_ceremony_companion(ceremony, ceremony_companion, f"{path}.ceremony")
    registered_public_key = provenance["registered_public_key"]
    if registered_public_key is None:
        raise VerificationError(f"{path} export provenance lacks a registered key")
    packages = _verify_export_package_set(
        vector["packages"], ceremony, provenance["pair_digest"], f"{path}.packages"
    )
    receipt = _verify_export_receipt(
        vector["receipt"],
        ceremony,
        provenance["pair_digest"],
        packages,
        registered_public_key,
        f"{path}.receipt",
    )
    _require_exact_value(
        _require_string(vector["state_effect"], f"{path}.state_effect"),
        "registered_state_retained",
        f"{path}.state_effect",
    )
    return {
        "case_id": case_id,
        "ceremony": ceremony,
        "packages": packages,
        "receipt": receipt,
    }


def _require_semantic_registered_key_continuity(
    origins: dict[str, dict[str, Any]], export: dict[str, Any]
) -> None:
    expected = export["receipt"]["registered_public_key"]
    for origin_kind in SEMANTIC_LIFECYCLE_ACTIVATION_ORIGINS_V1:
        actual = origins[origin_kind]["receipt"]["registered_public_key"]
        if actual != expected:
            raise VerificationError(
                f"semantic lifecycle {origin_kind} registered key differs from export"
            )


def _require_activation_control_origin(
    activation: dict[str, Any], origin: dict[str, Any], origin_kind: str, path: str
) -> None:
    authorization = activation["authorization_fields"]
    actual_origin_kind = _semantic_lifecycle_kind_from_tag(
        authorization[b"originRequestKind"], f"{path}.originRequestKind"
    )
    if actual_origin_kind != origin_kind:
        raise VerificationError(f"{path}.originRequestKind does not match the origin case")
    expected_authorization_fields = {
        b"originRequestContextDigest": origin["ceremony"]["request_digest"],
        b"originTranscriptDigest": origin["ceremony"]["transcript_digest"],
        b"packageSetDigest": origin["packages"]["package_set_digest"],
        b"activationEpoch": origin["packages"]["activation_epoch"].to_bytes(8, "big"),
    }
    for name, expected in expected_authorization_fields.items():
        if authorization[name] != expected:
            raise VerificationError(f"{path}.{name.decode('ascii')} does not match the origin")

    activation_request = activation["request_fields"]
    origin_request = origin["ceremony"]["request_fields"]
    fresh_labels = {
        b"requestKind",
        b"requestId",
        b"replayNonce",
        b"recipientPlan",
        b"outputPackageKind",
        b"requestExpiry",
    }
    for label in SEMANTIC_LIFECYCLE_REQUEST_CONTEXT_LABELS_V1:
        if label not in fresh_labels and activation_request[label] != origin_request[label]:
            raise VerificationError(
                f"{path}.request_context changed bound field {label.decode('ascii')}"
            )
    for label in (b"requestId", b"replayNonce"):
        if activation_request[label] == origin_request[label]:
            raise VerificationError(
                f"{path}.request_context did not refresh {label.decode('ascii')}"
            )
    if activation["request_digest"] == origin["ceremony"]["request_digest"]:
        raise VerificationError(f"{path}.request_digest must be origin-distinct")
    if (
        activation["transcript_fields"][b"transcriptNonce"]
        == origin["ceremony"]["transcript_fields"][b"transcriptNonce"]
    ):
        raise VerificationError(f"{path}.transcriptNonce must be origin-distinct")
    if activation["transcript_digest"] == origin["ceremony"]["transcript_digest"]:
        raise VerificationError(f"{path}.transcript_digest must be origin-distinct")


def _verify_zero_reevaluation(value: Any, path: str) -> None:
    counters = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_ZERO_REEVALUATION_KEY_ORDER, path
    )
    for field_name in SEMANTIC_LIFECYCLE_ZERO_REEVALUATION_KEY_ORDER:
        counter = _require_u8(counters[field_name], f"{path}.{field_name}")
        if counter != 0:
            raise VerificationError(f"{path}.{field_name} must equal zero")


def _derive_rejected_activation_attempt(
    value: Any, registration_origin: dict[str, Any], path: str
) -> dict[str, Any]:
    fresh = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_FRESH_FIELDS_KEY_ORDER, path
    )
    request_id = _ceremony_visible_ascii(fresh["request_id"], f"{path}.request_id")
    replay_nonce = _decode_hex(fresh["replay_nonce_hex"], 32, f"{path}.replay_nonce_hex")
    request_expiry = _ceremony_positive_u64(
        fresh["request_expiry"], f"{path}.request_expiry"
    )
    authorization_record_digest = _ceremony_nonzero_digest(
        fresh["authorization_record_digest_hex"],
        f"{path}.authorization_record_digest_hex",
    )
    transcript_nonce = _decode_hex(
        fresh["transcript_nonce_hex"], 32, f"{path}.transcript_nonce_hex"
    )
    transport_binding_digest = _ceremony_nonzero_digest(
        fresh["transport_binding_digest_hex"],
        f"{path}.transport_binding_digest_hex",
    )
    artifact_suite_digest = _ceremony_nonzero_digest(
        fresh["artifact_suite_digest_hex"], f"{path}.artifact_suite_digest_hex"
    )

    origin_request_fields = registration_origin["ceremony"]["request_fields"]
    request_fields = dict(origin_request_fields)
    request_fields[b"requestKind"] = b"\x02"
    request_fields[b"requestId"] = request_id
    request_fields[b"replayNonce"] = replay_nonce
    request_fields[b"recipientPlan"] = bytes(
        (CEREMONY_KIND_METADATA_V1["activation"][2],)
    )
    request_fields[b"outputPackageKind"] = bytes(
        (CEREMONY_KIND_METADATA_V1["activation"][4],)
    )
    request_fields[b"requestExpiry"] = request_expiry
    request_encoding = _lp32_join(
        (
            PUBLIC_REQUEST_CONTEXT_ENCODING_DOMAIN_V1,
            *_ceremony_labeled(
                tuple(
                    (label, request_fields[label])
                    for label in SEMANTIC_LIFECYCLE_REQUEST_CONTEXT_LABELS_V1
                )
            ),
        )
    )
    request_digest = hashlib.sha256(request_encoding).digest()

    committed = registration_origin["committed"]
    authorization_encoding = _lp32_join(
        (
            CEREMONY_AUTHORIZATION_DOMAINS_V1["activation"],
            *_ceremony_labeled(
                (
                    (b"requestKind", b"\x02"),
                    (b"publicRequestContextDigest", request_digest),
                    (b"authorizationRecordDigest", authorization_record_digest),
                    (b"originRequestKind", b"\x01"),
                    (
                        b"originRequestContextDigest",
                        registration_origin["ceremony"]["request_digest"],
                    ),
                    (
                        b"originTranscriptDigest",
                        registration_origin["ceremony"]["transcript_digest"],
                    ),
                    (b"packageSetDigest", committed["package_set_digest"]),
                    (
                        b"activationEpoch",
                        committed["activation_epoch"].to_bytes(8, "big"),
                    ),
                )
            ),
        )
    )
    authorization_digest = hashlib.sha256(authorization_encoding).digest()
    transcript_encoding = _lp32_join(
        (
            CEREMONY_TRANSCRIPT_ENCODING_DOMAIN_V1,
            *_ceremony_labeled(
                (
                    (b"protocolVersion", (1).to_bytes(8, "big")),
                    (b"protocolId", PROTOCOL_ID_V1.encode("ascii")),
                    (b"requestKind", b"\x02"),
                    (b"circuitId", ACTIVATION_CIRCUIT_ID_V1.encode("ascii")),
                    (b"publicRequestContextDigest", request_digest),
                    (b"authorizationDigest", authorization_digest),
                    (b"transcriptNonce", transcript_nonce),
                    (b"transportBindingDigest", transport_binding_digest),
                    (b"artifactSuiteDigest", artifact_suite_digest),
                )
            ),
        )
    )
    transcript_digest = hashlib.sha256(transcript_encoding).digest()
    return {
        "request_id": request_id,
        "replay_nonce": replay_nonce,
        "request_expiry": int.from_bytes(request_expiry, "big"),
        "transcript_nonce": transcript_nonce,
        "request_digest": request_digest,
        "authorization_digest": authorization_digest,
        "transcript_digest": transcript_digest,
    }


def _verify_semantic_activation_control_case(
    value: Any,
    origins: dict[str, dict[str, Any]],
    case_ids: set[str],
    path: str,
) -> dict[str, Any]:
    vector = _require_ordered_keys(
        value, SEMANTIC_LIFECYCLE_ACTIVATION_CONTROL_KEY_ORDER, path
    )
    case_id = _verify_semantic_lifecycle_case_id(
        vector["case_id"], case_ids, f"{path}.case_id"
    )
    metadata_consumed = vector["metadata_consumed"]
    if type(metadata_consumed) is not list or len(metadata_consumed) != 3:
        raise VerificationError(f"{path}.metadata_consumed must contain exactly three origins")
    normalized_metadata: list[dict[str, Any]] = []
    for index, origin_kind in enumerate(SEMANTIC_LIFECYCLE_ACTIVATION_ORIGINS_V1):
        item_path = f"{path}.metadata_consumed[{index}]"
        item = _require_ordered_keys(
            metadata_consumed[index],
            SEMANTIC_LIFECYCLE_METADATA_CONSUMED_KEY_ORDER,
            item_path,
        )
        _require_exact_value(
            _require_string(item["origin_kind"], f"{item_path}.origin_kind"),
            origin_kind,
            f"{item_path}.origin_kind",
        )
        origin = origins[origin_kind]
        _require_exact_value(
            _require_string(item["origin_case_id"], f"{item_path}.origin_case_id"),
            origin["case_id"],
            f"{item_path}.origin_case_id",
        )
        activation = _verify_semantic_ceremony_vector(
            item["activation_ceremony"], "activation", f"{item_path}.activation_ceremony"
        )
        _require_activation_control_origin(
            activation, origin, origin_kind, f"{item_path}.activation_ceremony"
        )
        _verify_metadata_consumed_persistence(
            item["persistence"],
            origin["committed"],
            activation,
            f"{item_path}.persistence",
        )
        _verify_zero_reevaluation(
            item["zero_reevaluation"], f"{item_path}.zero_reevaluation"
        )
        normalized_metadata.append(
            {
                "origin_kind": origin_kind,
                "origin_case_id": origin["case_id"],
                "committed": origin["committed"],
                "activation": activation,
            }
        )

    rejected_attempts = vector["rejected_attempts"]
    if type(rejected_attempts) is not list or len(rejected_attempts) != 4:
        raise VerificationError(f"{path}.rejected_attempts must contain four fixtures")
    registration_origin = origins["registration"]
    for index, fixture_class in enumerate(SEMANTIC_LIFECYCLE_REJECTION_CLASSES_V1):
        item_path = f"{path}.rejected_attempts[{index}]"
        item = _require_ordered_keys(
            rejected_attempts[index],
            SEMANTIC_LIFECYCLE_REJECTED_ATTEMPT_KEY_ORDER,
            item_path,
        )
        _require_exact_value(
            _require_string(item["fixture_class"], f"{item_path}.fixture_class"),
            fixture_class,
            f"{item_path}.fixture_class",
        )
        attempted = _derive_rejected_activation_attempt(
            item["fresh_fields"], registration_origin, f"{item_path}.fresh_fields"
        )
        rejected = _verify_attempt_rejected_persistence(
            item["persistence"],
            registration_origin["committed"],
            f"{item_path}.persistence",
        )
        if rejected["abort_transcript_digest"] != attempted["transcript_digest"]:
            raise VerificationError(f"{item_path} abort transcript digest was not reconstructed")
        origin_ceremony = registration_origin["ceremony"]
        origin_request = origin_ceremony["request_fields"]
        origin_request_id = origin_request[b"requestId"]
        origin_replay_nonce = origin_request[b"replayNonce"]
        origin_request_expiry = int.from_bytes(origin_request[b"requestExpiry"], "big")
        origin_transcript_nonce = origin_ceremony["transcript_fields"][b"transcriptNonce"]
        if fixture_class == "request_id":
            if attempted["request_id"] != origin_request_id:
                raise VerificationError(f"{item_path} does not reuse the origin request id")
            if (
                attempted["replay_nonce"] == origin_replay_nonce
                or attempted["request_expiry"] == origin_request_expiry
                or attempted["transcript_nonce"] == origin_transcript_nonce
            ):
                raise VerificationError(f"{item_path} request-id fixture reuses extra freshness")
        elif fixture_class == "replay_nonce":
            if attempted["replay_nonce"] != origin_replay_nonce:
                raise VerificationError(f"{item_path} does not reuse the origin replay nonce")
            if (
                attempted["request_id"] == origin_request_id
                or attempted["request_expiry"] == origin_request_expiry
                or attempted["transcript_nonce"] == origin_transcript_nonce
            ):
                raise VerificationError(f"{item_path} replay-nonce fixture reuses extra freshness")
        elif fixture_class == "transcript_nonce":
            if attempted["transcript_nonce"] != origin_transcript_nonce:
                raise VerificationError(f"{item_path} does not reuse the origin transcript nonce")
            if (
                attempted["request_id"] == origin_request_id
                or attempted["replay_nonce"] == origin_replay_nonce
                or attempted["request_expiry"] == origin_request_expiry
            ):
                raise VerificationError(
                    f"{item_path} transcript-nonce fixture reuses extra freshness"
                )
        elif (
            attempted["request_id"] != origin_request_id
            or attempted["replay_nonce"] != origin_replay_nonce
            or attempted["request_expiry"] != origin_request_expiry
            or attempted["transcript_nonce"] != origin_transcript_nonce
        ):
            raise VerificationError(
                f"{item_path} does not reuse the origin context and transcript freshness"
            )
    return {"case_id": case_id, "metadata_consumed": tuple(normalized_metadata)}


def _verified_semantic_lifecycle_details(
    corpus: Any,
    ceremony_context_corpus: Any,
    provenance_corpus: Any,
) -> dict[str, Any]:
    corpus_object = _require_ordered_keys(
        corpus, SEMANTIC_LIFECYCLE_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(corpus_object["schema"], "$.schema"),
        SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(corpus_object["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(corpus_object["evidence_scope"], "$.evidence_scope"),
        SEMANTIC_LIFECYCLE_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    _scan_semantic_lifecycle_public_boundary(corpus_object, "$")
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) != 5:
        raise VerificationError("$.cases must contain exactly five semantic lifecycle cases")
    for index, expected_kind in enumerate(SEMANTIC_LIFECYCLE_CASE_SEQUENCE_V1):
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], SEMANTIC_LIFECYCLE_CASE_KEY_ORDER, case_path
        )
        _require_exact_value(
            _require_string(case["request_kind"], f"{case_path}.request_kind"),
            expected_kind,
            f"{case_path}.request_kind",
        )
        vector = _require_object(case["vector"], f"{case_path}.vector")
        _require_exact_value(
            _require_string(vector.get("case_id"), f"{case_path}.vector.case_id"),
            SEMANTIC_LIFECYCLE_CASE_IDS_V1[index],
            f"{case_path}.vector.case_id",
        )

    ceremony_map = _verified_ceremony_encoding_map(ceremony_context_corpus)
    provenance_map = _verified_provenance_semantic_map(
        provenance_corpus, ceremony_context_corpus
    )
    case_ids: set[str] = set()
    origins = {
        "registration": _verify_semantic_activation_artifact_case(
            cases[0]["vector"],
            "registration",
            ceremony_map["registration"],
            provenance_map["registration"],
            case_ids,
            "$.cases[0].vector",
        ),
        "recovery": _verify_semantic_activation_artifact_case(
            cases[2]["vector"],
            "recovery",
            ceremony_map["recovery"],
            provenance_map["recovery"],
            case_ids,
            "$.cases[2].vector",
        ),
        "refresh": _verify_semantic_activation_artifact_case(
            cases[3]["vector"],
            "refresh",
            ceremony_map["refresh"],
            provenance_map["refresh"],
            case_ids,
            "$.cases[3].vector",
        ),
    }
    export = _verify_semantic_export_artifact_case(
        cases[4]["vector"],
        ceremony_map["export"],
        provenance_map["export"],
        case_ids,
        "$.cases[4].vector",
    )
    _require_semantic_registered_key_continuity(origins, export)
    activation_control = _verify_semantic_activation_control_case(
        cases[1]["vector"], origins, case_ids, "$.cases[1].vector"
    )
    return {
        "case_count": len(cases),
        "origins": origins,
        "activation_control": activation_control,
        "export": export,
    }


def verify_semantic_lifecycle_corpus(
    corpus: Any,
    ceremony_context_corpus: Any,
    provenance_corpus: Any,
) -> int:
    """Verifies public semantic artifacts and lifecycle projections independently."""
    details = _verified_semantic_lifecycle_details(
        corpus, ceremony_context_corpus, provenance_corpus
    )
    return details["case_count"]


def _output_party_activation_package_projection(
    value: Any, semantic_origin: dict[str, Any], path: str
) -> dict[str, Any]:
    projection = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_ACTIVATION_PACKAGE_PROJECTION_KEY_ORDER, path
    )
    descriptors = semantic_origin["packages"]["descriptors"]
    identities = (
        ("deriver_a_client", "deriver_a", "client", "client_scalar"),
        ("deriver_b_client", "deriver_b", "client", "client_scalar"),
        (
            "deriver_a_signing_worker",
            "deriver_a",
            "signing_worker",
            "signing_worker_scalar",
        ),
        (
            "deriver_b_signing_worker",
            "deriver_b",
            "signing_worker",
            "signing_worker_scalar",
        ),
    )
    expected_projection: dict[str, Any] = {}
    for index, (name, role, recipient, output_family) in enumerate(identities):
        member_path = f"{path}.{name}"
        member = _require_ordered_keys(
            projection[name],
            OUTPUT_PARTY_VIEWS_ACTIVATION_PACKAGE_MEMBER_KEY_ORDER,
            member_path,
        )
        _require_epoch(member["ciphertext_length"], f"{member_path}.ciphertext_length")
        descriptor = descriptors[index]
        expected = {
            "role": role,
            "recipient": recipient,
            "output_family": output_family,
            "recipient_key_binding_hex": descriptor["recipient_key_binding"].hex(),
            "share_point_hex": descriptor["scalar_share_point"].hex(),
            "recipient_protection_digest_hex": descriptor[
                "recipient_protection_digest"
            ].hex(),
            "recipient_ciphertext_digest_hex": descriptor[
                "recipient_ciphertext_digest"
            ].hex(),
            "ciphertext_length": descriptor["ciphertext_length"],
            "output_binding_digest_hex": descriptor["output_binding_digest"].hex(),
            "package_authentication_digest_hex": descriptor[
                "package_authentication_digest"
            ].hex(),
        }
        if member != expected:
            raise VerificationError(
                f"{member_path} differs from its semantic activation descriptor"
            )
        expected_projection[name] = expected
    return expected_projection


def _output_party_export_package_projection(
    value: Any, semantic_export: dict[str, Any], path: str
) -> dict[str, Any]:
    projection = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_EXPORT_PACKAGE_PROJECTION_KEY_ORDER, path
    )
    descriptors = semantic_export["packages"]["descriptors"]
    identities = (
        ("deriver_a_client", "deriver_a"),
        ("deriver_b_client", "deriver_b"),
    )
    expected_projection: dict[str, Any] = {}
    for index, (name, role) in enumerate(identities):
        member_path = f"{path}.{name}"
        member = _require_ordered_keys(
            projection[name],
            OUTPUT_PARTY_VIEWS_EXPORT_PACKAGE_MEMBER_KEY_ORDER,
            member_path,
        )
        _require_epoch(member["ciphertext_length"], f"{member_path}.ciphertext_length")
        descriptor = descriptors[index]
        expected = {
            "role": role,
            "recipient": "client",
            "output_family": "client_seed",
            "recipient_key_binding_hex": descriptor["recipient_key_binding"].hex(),
            "recipient_protection_digest_hex": descriptor[
                "recipient_protection_digest"
            ].hex(),
            "recipient_ciphertext_digest_hex": descriptor[
                "recipient_ciphertext_digest"
            ].hex(),
            "ciphertext_length": descriptor["ciphertext_length"],
            "output_binding_digest_hex": descriptor["output_binding_digest"].hex(),
            "package_authentication_digest_hex": descriptor[
                "package_authentication_digest"
            ].hex(),
        }
        if member != expected:
            raise VerificationError(
                f"{member_path} differs from its semantic export descriptor"
            )
        expected_projection[name] = expected
    return expected_projection


def _verify_output_party_activation_common(
    value: Any,
    request_kind: str,
    stage: str,
    semantic_origin: dict[str, Any],
    path: str,
) -> None:
    common = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_ACTIVATION_COMMON_KEY_ORDER, path
    )
    _require_epoch(common["activation_epoch"], f"{path}.activation_epoch")
    package_projection = _output_party_activation_package_projection(
        common["package_projection"], semantic_origin, f"{path}.package_projection"
    )
    ceremony = semantic_origin["ceremony"]
    packages = semantic_origin["packages"]
    receipt = semantic_origin["receipt"]
    binding = packages["binding"]
    expected = {
        "semantic_lifecycle_case_id": semantic_origin["case_id"],
        "stage": stage,
        "request_kind": request_kind,
        "circuit_id": ACTIVATION_CIRCUIT_ID_V1,
        "public_request_context_digest_hex": ceremony["request_digest"].hex(),
        "authorization_digest_hex": ceremony["authorization_digest"].hex(),
        "transcript_digest_hex": ceremony["transcript_digest"].hex(),
        "transport_binding_digest_hex": binding["transport_digest"].hex(),
        "artifact_suite_digest_hex": binding["artifact_digest"].hex(),
        "one_use_execution_id_hex": binding["one_use_execution_id"].hex(),
        "input_provenance_pair_digest_hex": binding[
            "input_provenance_digest"
        ].hex(),
        "host_reference_evaluation_evidence_digest_hex": binding[
            "evaluation_evidence_digest"
        ].hex(),
        "package_projection": package_projection,
        "package_set_digest_hex": packages["package_set_digest"].hex(),
        "receipt_body_digest_hex": receipt["receipt_digest"].hex(),
        "activation_epoch": packages["activation_epoch"],
        "registered_public_key_hex": receipt["registered_public_key"].hex(),
        "x_client_hex": receipt["x_client"].hex(),
        "x_server_hex": receipt["x_server"].hex(),
        "deriver_a_receipt_evidence_digest_hex": receipt[
            "deriver_a_receipt_evidence_digest"
        ].hex(),
        "deriver_b_receipt_evidence_digest_hex": receipt[
            "deriver_b_receipt_evidence_digest"
        ].hex(),
        "terminal_state": "output_committed",
    }
    if common != expected:
        raise VerificationError(f"{path} differs from its semantic lifecycle source")


def _verify_output_party_metadata_common(
    value: Any, semantic_control: dict[str, Any], path: str
) -> None:
    common = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_METADATA_COMMON_KEY_ORDER, path
    )
    projections = common["origin_metadata_projections"]
    metadata = semantic_control["metadata_consumed"]
    if type(projections) is not list or len(projections) != len(metadata):
        raise VerificationError(
            f"{path}.origin_metadata_projections must contain exactly three origins"
        )
    expected_projections: list[dict[str, Any]] = []
    for index, source in enumerate(metadata):
        projection_path = f"{path}.origin_metadata_projections[{index}]"
        projection = _require_ordered_keys(
            projections[index],
            OUTPUT_PARTY_VIEWS_METADATA_PROJECTION_KEY_ORDER,
            projection_path,
        )
        _require_epoch(projection["activation_epoch"], f"{projection_path}.activation_epoch")
        _verify_zero_reevaluation(
            projection["zero_reevaluation"], f"{projection_path}.zero_reevaluation"
        )
        committed = source["committed"]
        activation = source["activation"]
        expected_projection = {
            "origin_kind": source["origin_kind"],
            "origin_case_id": source["origin_case_id"],
            "origin_request_context_digest_hex": committed[
                "origin_request_context_digest"
            ].hex(),
            "origin_authorization_digest_hex": committed[
                "origin_authorization_digest"
            ].hex(),
            "origin_transcript_digest_hex": committed[
                "origin_transcript_digest"
            ].hex(),
            "one_use_execution_id_hex": committed["one_use_execution_id"].hex(),
            "package_set_digest_hex": committed["package_set_digest"].hex(),
            "receipt_body_digest_hex": committed["receipt_digest"].hex(),
            "activation_epoch": committed["activation_epoch"],
            "registered_public_key_hex": committed["registered_public_key"].hex(),
            "activation_request_context_digest_hex": activation[
                "request_digest"
            ].hex(),
            "activation_authorization_digest_hex": activation[
                "authorization_digest"
            ].hex(),
            "activation_transcript_digest_hex": activation[
                "transcript_digest"
            ].hex(),
            "terminal_state": "metadata_consumed",
            "zero_reevaluation": {
                "yao_evaluations": 0,
                "deriver_a_invocations": 0,
                "deriver_b_invocations": 0,
                "contribution_derivations": 0,
                "output_share_samples": 0,
            },
        }
        if projection != expected_projection:
            raise VerificationError(
                f"{projection_path} differs from semantic activation metadata"
            )
        expected_projections.append(expected_projection)
    expected = {
        "semantic_lifecycle_case_id": semantic_control["case_id"],
        "stage": "activation_metadata_consumed",
        "request_kind": "activation",
        "circuit_id": ACTIVATION_CIRCUIT_ID_V1,
        "origin_metadata_projections": expected_projections,
    }
    if common != expected:
        raise VerificationError(f"{path} differs from semantic activation control")


def _verify_output_party_export_common(
    value: Any, semantic_export: dict[str, Any], path: str
) -> None:
    common = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_EXPORT_COMMON_KEY_ORDER, path
    )
    package_projection = _output_party_export_package_projection(
        common["package_projection"], semantic_export, f"{path}.package_projection"
    )
    ceremony = semantic_export["ceremony"]
    packages = semantic_export["packages"]
    receipt = semantic_export["receipt"]
    binding = packages["binding"]
    expected = {
        "semantic_lifecycle_case_id": semantic_export["case_id"],
        "stage": "export_released",
        "request_kind": "export",
        "circuit_id": EXPORT_CIRCUIT_ID_V1,
        "public_request_context_digest_hex": ceremony["request_digest"].hex(),
        "authorization_digest_hex": ceremony["authorization_digest"].hex(),
        "transcript_digest_hex": ceremony["transcript_digest"].hex(),
        "transport_binding_digest_hex": binding["transport_digest"].hex(),
        "artifact_suite_digest_hex": binding["artifact_digest"].hex(),
        "one_use_execution_id_hex": binding["one_use_execution_id"].hex(),
        "input_provenance_pair_digest_hex": binding[
            "input_provenance_digest"
        ].hex(),
        "host_reference_evaluation_evidence_digest_hex": binding[
            "evaluation_evidence_digest"
        ].hex(),
        "package_projection": package_projection,
        "package_set_digest_hex": packages["package_set_digest"].hex(),
        "receipt_body_digest_hex": receipt["receipt_digest"].hex(),
        "registered_public_key_hex": receipt["registered_public_key"].hex(),
        "output_committed_receipt_digest_hex": receipt[
            "output_committed_receipt_digest"
        ].hex(),
        "client_delivery_evidence_digest_hex": receipt[
            "client_delivery_evidence_digest"
        ].hex(),
        "export_authorization_consumption_evidence_digest_hex": receipt[
            "export_authorization_consumption_evidence_digest"
        ].hex(),
        "terminal_state": "export_released",
        "state_effect": "registered_state_retained",
    }
    if common != expected:
        raise VerificationError(f"{path} differs from its semantic lifecycle source")


def _verify_output_party_empty_extension(value: Any, expected_kind: str, path: str) -> None:
    extension = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_EMPTY_EXTENSION_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(extension["kind"], f"{path}.kind"),
        expected_kind,
        f"{path}.kind",
    )


def _verify_output_party_activation_extensions(
    value: Any, semantic_origin: dict[str, Any], path: str
) -> tuple[dict[str, Any], frozenset[str]]:
    extensions = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_ROLE_EXTENSIONS_KEY_ORDER, path
    )
    shares: list[int] = []
    private_values: set[str] = set()
    for role, expected_kind in (
        ("deriver_a", "deriver_a_activation_scalar_shares"),
        ("deriver_b", "deriver_b_activation_scalar_shares"),
    ):
        role_path = f"{path}.{role}"
        extension = _require_ordered_keys(
            extensions[role],
            OUTPUT_PARTY_VIEWS_ACTIVATION_SHARE_EXTENSION_KEY_ORDER,
            role_path,
        )
        _require_exact_value(
            _require_string(extension["kind"], f"{role_path}.kind"),
            expected_kind,
            f"{role_path}.kind",
        )
        for field_name in (
            "client_scalar_share_hex",
            "signing_worker_scalar_share_hex",
        ):
            shares.append(_decode_scalar(extension[field_name], f"{role_path}.{field_name}"))
            private_values.add(extension[field_name])

    client_path = f"{path}.client"
    client = _require_ordered_keys(
        extensions["client"],
        OUTPUT_PARTY_VIEWS_EMPTY_EXTENSION_KEY_ORDER,
        client_path,
    )
    _require_exact_value(
        _require_string(client["kind"], f"{client_path}.kind"),
        "client_no_private_output",
        f"{client_path}.kind",
    )

    for role, kind in (
        ("signing_worker", "signing_worker_no_private_output"),
        ("router", "router_no_private_output"),
        ("observer", "observer_no_private_output"),
        ("diagnostics_logs", "diagnostics_logs_no_private_output"),
    ):
        _verify_output_party_empty_extension(
            extensions[role], kind, f"{path}.{role}"
        )

    a_client, a_worker, b_client, b_worker = shares
    descriptors = semantic_origin["packages"]["descriptors"]
    for index, scalar in enumerate((a_client, b_client, a_worker, b_worker)):
        actual_point = _compress_point(_multiply_base(scalar))
        if actual_point != descriptors[index]["scalar_share_point"]:
            raise VerificationError(
                f"{path} role-local scalar share {index} differs from its descriptor point"
            )
    reconstructed_client = (a_client + b_client) % SCALAR_ORDER
    reconstructed_worker = (a_worker + b_worker) % SCALAR_ORDER
    receipt = semantic_origin["receipt"]
    if _compress_point(_multiply_base(reconstructed_client)) != receipt["x_client"]:
        raise VerificationError(f"{path} Client shares do not reconstruct X_client")
    if _compress_point(_multiply_base(reconstructed_worker)) != receipt["x_server"]:
        raise VerificationError(f"{path} SigningWorker shares do not reconstruct X_server")
    _require_activation_public_relation(
        receipt["x_client"],
        receipt["x_server"],
        receipt["registered_public_key"],
        f"{path}.registered_public_key_relation",
    )
    return extensions, frozenset(private_values)


def _verify_output_party_metadata_extensions(
    value: Any, path: str
) -> dict[str, Any]:
    extensions = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_ROLE_EXTENSIONS_KEY_ORDER, path
    )
    kinds = (
        ("deriver_a", "deriver_a_no_new_private_output"),
        ("deriver_b", "deriver_b_no_new_private_output"),
        ("client", "client_no_new_private_output"),
        ("signing_worker", "signing_worker_no_new_private_output"),
        ("router", "router_no_new_private_output"),
        ("observer", "observer_no_new_private_output"),
        ("diagnostics_logs", "diagnostics_logs_no_new_private_output"),
    )
    for role, kind in kinds:
        _verify_output_party_empty_extension(
            extensions[role], kind, f"{path}.{role}"
        )
    return extensions


def _derive_ed25519_public_key_from_seed(seed: bytes) -> bytes:
    digest = hashlib.sha512(seed).digest()
    clamped = bytearray(digest[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    return _compress_point(_multiply_base(int.from_bytes(clamped, "little")))


def _verify_output_party_export_extensions(
    value: Any, semantic_export: dict[str, Any], path: str
) -> tuple[dict[str, Any], frozenset[str]]:
    extensions = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_ROLE_EXTENSIONS_KEY_ORDER, path
    )
    seed_shares: list[bytes] = []
    private_values: set[str] = set()
    for role, expected_kind in (
        ("deriver_a", "deriver_a_seed_share"),
        ("deriver_b", "deriver_b_seed_share"),
    ):
        role_path = f"{path}.{role}"
        extension = _require_ordered_keys(
            extensions[role],
            OUTPUT_PARTY_VIEWS_EXPORT_SHARE_EXTENSION_KEY_ORDER,
            role_path,
        )
        _require_exact_value(
            _require_string(extension["kind"], f"{role_path}.kind"),
            expected_kind,
            f"{role_path}.kind",
        )
        seed_shares.append(
            _decode_hex(extension["seed_share_hex"], 32, f"{role_path}.seed_share_hex")
        )
        private_values.add(extension["seed_share_hex"])

    client_path = f"{path}.client"
    client = _require_ordered_keys(
        extensions["client"],
        OUTPUT_PARTY_VIEWS_CLIENT_EXPORT_EXTENSION_KEY_ORDER,
        client_path,
    )
    _require_exact_value(
        _require_string(client["kind"], f"{client_path}.kind"),
        "client_authorized_seed",
        f"{client_path}.kind",
    )
    seed = _decode_hex(client["seed_hex"], 32, f"{client_path}.seed_hex")
    private_values.add(client["seed_hex"])
    _verify_output_party_empty_extension(
        extensions["signing_worker"],
        "signing_worker_no_export_output",
        f"{path}.signing_worker",
    )
    for role, kind in (
        ("router", "router_no_private_output"),
        ("observer", "observer_no_private_output"),
        ("diagnostics_logs", "diagnostics_logs_no_private_output"),
    ):
        _verify_output_party_empty_extension(
            extensions[role], kind, f"{path}.{role}"
        )

    reconstructed = _wrapping_add_256(seed_shares[0], seed_shares[1])
    if reconstructed != seed:
        raise VerificationError(f"{path} export seed shares do not reconstruct Client seed d")
    registered_public_key = semantic_export["receipt"]["registered_public_key"]
    if _derive_ed25519_public_key_from_seed(seed) != registered_public_key:
        raise VerificationError(f"{client_path}.seed_hex does not derive registered A_pub")
    return extensions, frozenset(private_values)


def _verify_output_party_static_observations(
    value: Any,
    extensions: dict[str, Any],
    case_id: str,
    stage: str,
    path: str,
) -> None:
    observations = _require_ordered_keys(
        value, OUTPUT_PARTY_VIEWS_STATIC_OBSERVATIONS_KEY_ORDER, path
    )
    for role, observation_kind in (
        ("deriver_a", "static_consuming_deriver_a"),
        ("deriver_b", "static_consuming_deriver_b"),
    ):
        observation_path = f"{path}.{role}"
        observation = _require_ordered_keys(
            observations[role],
            OUTPUT_PARTY_VIEWS_STATIC_OBSERVATION_KEY_ORDER,
            observation_path,
        )
        expected = {
            "observation_kind": observation_kind,
            "source_case_id": case_id,
            "source_stage": stage,
            "extension": extensions[role],
        }
        extension = _require_object(
            observation["extension"], f"{observation_path}.extension"
        )
        if (
            list(observation.items()) != list(expected.items())
            or tuple(extension) != tuple(extensions[role])
        ):
            raise VerificationError(
                f"{observation_path} is not an exact copy of its consuming role extension"
            )


def _known_output_party_private_values() -> frozenset[str]:
    roots = (
        LIFECYCLE_CLIENT_ROOT_V1,
        LIFECYCLE_DERIVER_A_ROOT_V1,
        LIFECYCLE_DERIVER_B_ROOT_V1,
    )
    application_encoding = b"".join(
        (
            _length_prefix_u32(APPLICATION_BINDING_DOMAIN_V1),
            _length_prefix_u32(APPLICATION_BINDING_WALLET_ID_LABEL_V1),
            _length_prefix_u32(LIFECYCLE_WALLET_ID_V1.encode("ascii")),
            _length_prefix_u32(APPLICATION_BINDING_SIGNING_KEY_ID_LABEL_V1),
            _length_prefix_u32(LIFECYCLE_SIGNING_KEY_ID_V1.encode("ascii")),
            _length_prefix_u32(APPLICATION_BINDING_SIGNING_ROOT_ID_LABEL_V1),
            _length_prefix_u32(LIFECYCLE_SIGNING_ROOT_ID_V1.encode("ascii")),
            _length_prefix_u32(APPLICATION_BINDING_KEY_CREATION_SIGNER_SLOT_LABEL_V1),
            _length_prefix_u32(LIFECYCLE_KEY_CREATION_SIGNER_SLOT_V1.to_bytes(4, "big")),
        )
    )
    application_digest = hashlib.sha256(application_encoding).digest()
    context_encoding = (
        STABLE_CONTEXT_DOMAIN_V1
        + application_digest
        + (1).to_bytes(2, "big")
        + (2).to_bytes(2, "big")
    )
    context_binding = hashlib.sha256(
        STABLE_CONTEXT_BINDING_DOMAIN_V1 + context_encoding
    ).digest()
    client_a_y, client_a_tau = _derive_kdf_contribution(
        roots[0], context_binding, 0x01, 0x01
    )
    client_b_y, client_b_tau = _derive_kdf_contribution(
        roots[0], context_binding, 0x02, 0x01
    )
    server_a_y, server_a_tau = _derive_kdf_contribution(
        roots[1], context_binding, 0x01, 0x02
    )
    server_b_y, server_b_tau = _derive_kdf_contribution(
        roots[2], context_binding, 0x02, 0x02
    )
    contributions = (
        client_a_y,
        client_a_tau,
        client_b_y,
        client_b_tau,
        server_a_y,
        server_a_tau,
        server_b_y,
        server_b_tau,
    )
    private_values = set(roots + contributions)

    def add_trace(
        y_client_a: bytes,
        tau_client_a: bytes,
        y_client_b: bytes,
        tau_client_b: bytes,
        y_server_a: bytes,
        tau_server_a: bytes,
        y_server_b: bytes,
        tau_server_b: bytes,
    ) -> None:
        y_a = _wrapping_add_256(y_client_a, y_server_a)
        y_b = _wrapping_add_256(y_client_b, y_server_b)
        seed = _wrapping_add_256(y_a, y_b)
        digest = hashlib.sha512(seed).digest()
        clamped = bytearray(digest[:32])
        clamped[0] &= 248
        clamped[31] &= 63
        clamped[31] |= 64
        signing_scalar = int.from_bytes(clamped, "little") % SCALAR_ORDER
        tau_a = (
            int.from_bytes(tau_client_a, "little")
            + int.from_bytes(tau_server_a, "little")
        ) % SCALAR_ORDER
        tau_b = (
            int.from_bytes(tau_client_b, "little")
            + int.from_bytes(tau_server_b, "little")
        ) % SCALAR_ORDER
        tau = (tau_a + tau_b) % SCALAR_ORDER
        private_values.update(
            {
                y_a,
                y_b,
                seed,
                digest,
                bytes(clamped),
                _encode_scalar(signing_scalar),
                _encode_scalar(tau_a),
                _encode_scalar(tau_b),
                _encode_scalar(tau),
                _encode_scalar(signing_scalar + tau),
                _encode_scalar(signing_scalar + 2 * tau),
            }
        )

    add_trace(
        client_a_y,
        client_a_tau,
        client_b_y,
        client_b_tau,
        server_a_y,
        server_a_tau,
        server_b_y,
        server_b_tau,
    )
    delta_y = bytes((0xA5,)) * 32
    delta_tau = _encode_scalar(17)
    refreshed_server_a_y = _wrapping_add_256(server_a_y, delta_y)
    refreshed_server_b_y = _wrapping_sub_256(server_b_y, delta_y)
    refreshed_server_a_tau = _encode_scalar(int.from_bytes(server_a_tau, "little") + 17)
    refreshed_server_b_tau = _encode_scalar(int.from_bytes(server_b_tau, "little") - 17)
    private_values.update(
        {
            delta_y,
            delta_tau,
            refreshed_server_a_y,
            refreshed_server_b_y,
            refreshed_server_a_tau,
            refreshed_server_b_tau,
        }
    )
    add_trace(
        client_a_y,
        client_a_tau,
        client_b_y,
        client_b_tau,
        refreshed_server_a_y,
        refreshed_server_a_tau,
        refreshed_server_b_y,
        refreshed_server_b_tau,
    )
    private_values.update(
        _encode_scalar(value)
        for value in (
            0,
            1,
            2,
            3,
            5,
            SCALAR_ORDER - 1,
            SCALAR_ORDER - 2,
        )
    )
    private_values.update(
        {
            bytes(32),
            (1).to_bytes(32, "little"),
            bytes((0xFF,)) * 32,
            bytes((0x77,)) * 32,
        }
    )
    return frozenset(value.hex() for value in private_values)


def _output_party_private_value_path_allowed(path: tuple[str | int, ...]) -> bool:
    if len(path) < 6 or path[:1] != ("cases",):
        return False
    case_index = path[1]
    package_cases = {0, 2, 3}
    if case_index in package_cases:
        role_prefix = ("cases", case_index, "vector", "role_extensions")
        if len(path) == 6 and path[:4] == role_prefix:
            role = path[4]
            field = path[5]
            if role in {"deriver_a", "deriver_b"}:
                return field in {
                    "client_scalar_share_hex",
                    "signing_worker_scalar_share_hex",
                }
            return False
        static_prefix = (
            "cases",
            case_index,
            "vector",
            "static_deriver_observations",
        )
        if len(path) == 7 and path[:4] == static_prefix and path[5] == "extension":
            return path[4] in {"deriver_a", "deriver_b"} and path[6] in {
                "client_scalar_share_hex",
                "signing_worker_scalar_share_hex",
            }
    if case_index == 4:
        role_prefix = ("cases", 4, "vector", "role_extensions")
        if len(path) == 6 and path[:4] == role_prefix:
            role = path[4]
            field = path[5]
            if role in {"deriver_a", "deriver_b"}:
                return field == "seed_share_hex"
            return role == "client" and field == "seed_hex"
        static_prefix = (
            "cases",
            4,
            "vector",
            "static_deriver_observations",
        )
        return (
            len(path) == 7
            and path[:4] == static_prefix
            and path[4] in {"deriver_a", "deriver_b"}
            and path[5] == "extension"
            and path[6] == "seed_share_hex"
        )
    return False


def _output_party_path(path: tuple[str | int, ...]) -> str:
    rendered = "$"
    for component in path:
        if type(component) is int:
            rendered += f"[{component}]"
        else:
            rendered += f".{component}"
    return rendered


def _output_party_public_cryptographic_value_path(
    path: tuple[str | int, ...]
) -> bool:
    if not path or type(path[-1]) is not str:
        return False
    field_name = path[-1]
    return (
        field_name.endswith("_digest_hex")
        or field_name.endswith("_binding_hex")
        or field_name.endswith("_key_hex")
        or field_name in {"share_point_hex", "x_client_hex", "x_server_hex"}
    )


def _scan_output_party_private_boundary(
    value: Any,
    known_private_values: frozenset[str],
    role_private_values: frozenset[str],
    path: tuple[str | int, ...] = (),
) -> None:
    if type(value) is dict:
        for key, nested in value.items():
            nested_path = path + (key,)
            if key in OUTPUT_PARTY_VIEWS_FORBIDDEN_KEYS_V1 or any(
                key.endswith(suffix)
                for suffix in OUTPUT_PARTY_VIEWS_FORBIDDEN_KEY_SUFFIXES_V1
            ):
                raise VerificationError(
                    f"{_output_party_path(nested_path)} is forbidden in output party views"
                )
            _scan_output_party_private_boundary(
                nested, known_private_values, role_private_values, nested_path
            )
        return
    if type(value) is list:
        for index, nested in enumerate(value):
            _scan_output_party_private_boundary(
                nested,
                known_private_values,
                role_private_values,
                path + (index,),
            )
        return
    if (
        type(value) is str
        and not _output_party_public_cryptographic_value_path(path)
        and (value in known_private_values or value in role_private_values)
        and not _output_party_private_value_path_allowed(path)
    ):
        raise VerificationError(
            f"{_output_party_path(path)} exposes known synthetic private material"
        )


def verify_output_party_views_corpus(
    corpus: Any,
    semantic_lifecycle_corpus: Any,
    ceremony_context_corpus: Any,
    provenance_corpus: Any,
) -> int:
    """Verifies strict host-only output-custody party views independently."""
    semantic = _verified_semantic_lifecycle_details(
        semantic_lifecycle_corpus, ceremony_context_corpus, provenance_corpus
    )
    corpus_object = _require_ordered_keys(
        corpus, OUTPUT_PARTY_VIEWS_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(corpus_object["schema"], "$.schema"),
        OUTPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(corpus_object["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(corpus_object["evidence_scope"], "$.evidence_scope"),
        OUTPUT_PARTY_VIEWS_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) != len(OUTPUT_PARTY_VIEWS_CASE_SEQUENCE_V1):
        raise VerificationError("$.cases must contain exactly five output party-view cases")

    private_values: set[str] = set()
    for index, expected in enumerate(OUTPUT_PARTY_VIEWS_CASE_SEQUENCE_V1):
        request_kind, case_id, stage, semantic_case_id = expected
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], OUTPUT_PARTY_VIEWS_CASE_KEY_ORDER, case_path
        )
        _require_exact_value(
            _require_string(case["request_kind"], f"{case_path}.request_kind"),
            request_kind,
            f"{case_path}.request_kind",
        )
        vector_path = f"{case_path}.vector"
        vector = _require_ordered_keys(
            case["vector"], OUTPUT_PARTY_VIEWS_VECTOR_KEY_ORDER, vector_path
        )
        _require_exact_value(
            _require_string(vector["case_id"], f"{vector_path}.case_id"),
            case_id,
            f"{vector_path}.case_id",
        )
        _require_exact_value(
            _require_string(vector["stage"], f"{vector_path}.stage"),
            stage,
            f"{vector_path}.stage",
        )

        if request_kind in SEMANTIC_LIFECYCLE_ACTIVATION_ORIGINS_V1:
            semantic_origin = semantic["origins"][request_kind]
            _require_exact_value(
                semantic_origin["case_id"], semantic_case_id, f"{vector_path}.semantic_case"
            )
            _verify_output_party_activation_common(
                vector["common_public"],
                request_kind,
                stage,
                semantic_origin,
                f"{vector_path}.common_public",
            )
            extensions, case_private_values = _verify_output_party_activation_extensions(
                vector["role_extensions"],
                semantic_origin,
                f"{vector_path}.role_extensions",
            )
            private_values.update(case_private_values)
        elif request_kind == "activation":
            semantic_control = semantic["activation_control"]
            _require_exact_value(
                semantic_control["case_id"], semantic_case_id, f"{vector_path}.semantic_case"
            )
            _verify_output_party_metadata_common(
                vector["common_public"],
                semantic_control,
                f"{vector_path}.common_public",
            )
            extensions = _verify_output_party_metadata_extensions(
                vector["role_extensions"], f"{vector_path}.role_extensions"
            )
        else:
            semantic_export = semantic["export"]
            _require_exact_value(
                semantic_export["case_id"], semantic_case_id, f"{vector_path}.semantic_case"
            )
            _verify_output_party_export_common(
                vector["common_public"],
                semantic_export,
                f"{vector_path}.common_public",
            )
            extensions, case_private_values = _verify_output_party_export_extensions(
                vector["role_extensions"],
                semantic_export,
                f"{vector_path}.role_extensions",
            )
            private_values.update(case_private_values)

        _verify_output_party_static_observations(
            vector["static_deriver_observations"],
            extensions,
            case_id,
            stage,
            f"{vector_path}.static_deriver_observations",
        )

    _scan_output_party_private_boundary(
        corpus_object,
        _known_output_party_private_values(),
        frozenset(private_values),
    )
    return len(cases)


def _verify_export_delivery_zero_work(value: Any, path: str) -> None:
    counts = _require_ordered_keys(value, EXPORT_DELIVERY_ZERO_WORK_KEY_ORDER, path)
    for name, count in counts.items():
        if type(count) is not int or count != 0:
            raise VerificationError(f"{path}.{name} must equal zero")


def verify_export_delivery_corpus(corpus: Any) -> int:
    """Verifies export output commitment, release, and redelivery independently."""
    document = _require_ordered_keys(corpus, EXPORT_DELIVERY_CORPUS_KEY_ORDER, "$")
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        EXPORT_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = document["cases"]
    if type(cases) is not list or len(cases) != 1:
        raise VerificationError("$.cases must contain exactly one export-delivery case")
    case = _require_ordered_keys(cases[0], EXPORT_DELIVERY_CASE_KEY_ORDER, "$.cases[0]")
    _require_exact_value(
        _require_string(case["case_id"], "$.cases[0].case_id"),
        "export_output_commit_release_redelivery_v1",
        "$.cases[0].case_id",
    )
    _require_exact_value(
        _require_string(case["request_kind"], "$.cases[0].request_kind"),
        "export",
        "$.cases[0].request_kind",
    )
    _require_exact_value(
        _require_string(
            case["semantic_lifecycle_case_id"],
            "$.cases[0].semantic_lifecycle_case_id",
        ),
        "export_semantic_artifacts_host_reference_receipt_v1",
        "$.cases[0].semantic_lifecycle_case_id",
    )

    committed_path = "$.cases[0].output_committed"
    committed = _require_ordered_keys(
        case["output_committed"],
        EXPORT_DELIVERY_OUTPUT_COMMITTED_KEY_ORDER,
        committed_path,
    )
    request_digest = _decode_hex(
        committed["request_context_digest_hex"], 32, f"{committed_path}.request_context_digest_hex"
    )
    authorization_digest = _decode_hex(
        committed["authorization_digest_hex"], 32, f"{committed_path}.authorization_digest_hex"
    )
    transcript_digest = _decode_hex(
        committed["transcript_digest_hex"], 32, f"{committed_path}.transcript_digest_hex"
    )
    package_digest = _decode_hex(
        committed["package_set_digest_hex"], 32, f"{committed_path}.package_set_digest_hex"
    )
    registered_key = _decode_hex(
        committed["registered_public_key_hex"], 32, f"{committed_path}.registered_public_key_hex"
    )
    _verify_registered_public_key(registered_key, f"{committed_path}.registered_public_key_hex")
    committed_encoding = _decode_variable_hex(
        committed["output_committed_receipt_encoding_hex"],
        f"{committed_path}.output_committed_receipt_encoding_hex",
    )
    committed_fields = _parse_lp32_fields(
        committed_encoding,
        16,
        f"{committed_path}.output_committed_receipt_encoding_hex",
    )
    if committed_fields[0] != EXPORT_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1:
        raise VerificationError(f"{committed_path} has the wrong output-committed domain")
    if committed_fields[1] != b"\x01" or committed_fields[2] != b"\x01" or committed_fields[3] != b"\x05":
        raise VerificationError(f"{committed_path} has invalid output-committed tags")
    for actual, expected, name in (
        (committed_fields[4], request_digest, "request_context_digest"),
        (committed_fields[5], authorization_digest, "authorization_digest"),
        (committed_fields[6], transcript_digest, "transcript_digest"),
        (committed_fields[12], package_digest, "package_set_digest"),
        (committed_fields[13], registered_key, "registered_public_key"),
    ):
        if actual != expected:
            raise VerificationError(f"{committed_path}.{name} disagrees with its receipt")
    for index, field_name in (
        (14, "deriver_a_receipt_evidence_digest_hex"),
        (15, "deriver_b_receipt_evidence_digest_hex"),
    ):
        evidence = _decode_hex(committed[field_name], 32, f"{committed_path}.{field_name}")
        _require_nonzero_bytes(evidence, 32, f"{committed_path}.{field_name}")
        if committed_fields[index] != evidence:
            raise VerificationError(f"{committed_path}.{field_name} disagrees with its receipt")
    committed_receipt_digest = _digest_encoding(
        EXPORT_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1, committed_encoding
    )
    _require_expected_bytes(
        committed["output_committed_receipt_digest_hex"],
        committed_receipt_digest,
        f"{committed_path}.output_committed_receipt_digest_hex",
    )
    if type(committed["active_state_version"]) is not int or committed["active_state_version"] <= 0:
        raise VerificationError(f"{committed_path}.active_state_version must be positive")
    _require_exact_value(
        _require_string(committed["authorization_state"], f"{committed_path}.authorization_state"),
        "unconsumed",
        f"{committed_path}.authorization_state",
    )

    uncertain_path = "$.cases[0].delivery_uncertain"
    uncertain = _require_ordered_keys(
        case["delivery_uncertain"], EXPORT_DELIVERY_UNCERTAIN_KEY_ORDER, uncertain_path
    )
    for name in ("before_package_set_digest_hex", "after_package_set_digest_hex"):
        if _decode_hex(uncertain[name], 32, f"{uncertain_path}.{name}") != package_digest:
            raise VerificationError(f"{uncertain_path}.{name} must preserve the package set")
    _require_exact_value(
        _require_string(uncertain["authorization_state"], f"{uncertain_path}.authorization_state"),
        "unconsumed",
        f"{uncertain_path}.authorization_state",
    )
    _verify_export_delivery_zero_work(
        uncertain["zero_private_evaluation_work"],
        f"{uncertain_path}.zero_private_evaluation_work",
    )

    released_path = "$.cases[0].released"
    released = _require_ordered_keys(
        case["released"], EXPORT_DELIVERY_RELEASED_KEY_ORDER, released_path
    )
    if _decode_hex(released["package_set_digest_hex"], 32, f"{released_path}.package_set_digest_hex") != package_digest:
        raise VerificationError(f"{released_path}.package_set_digest_hex changed")
    if _decode_hex(released["output_committed_receipt_digest_hex"], 32, f"{released_path}.output_committed_receipt_digest_hex") != committed_receipt_digest:
        raise VerificationError(f"{released_path}.output_committed_receipt_digest_hex changed")
    released_encoding = _decode_variable_hex(
        released["released_receipt_encoding_hex"], f"{released_path}.released_receipt_encoding_hex"
    )
    released_fields = _parse_lp32_fields(
        released_encoding, 17, f"{released_path}.released_receipt_encoding_hex"
    )
    if released_fields[0] != EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1:
        raise VerificationError(f"{released_path} has the wrong released domain")
    if released_fields[1] != b"\x02" or released_fields[2] != b"\x02" or released_fields[3] != b"\x05":
        raise VerificationError(f"{released_path} has invalid released tags")
    for actual, expected, name in (
        (released_fields[4], request_digest, "request_context_digest"),
        (released_fields[5], authorization_digest, "authorization_digest"),
        (released_fields[6], transcript_digest, "transcript_digest"),
        (released_fields[12], package_digest, "package_set_digest"),
        (released_fields[13], registered_key, "registered_public_key"),
        (released_fields[14], committed_receipt_digest, "output_committed_receipt_digest"),
    ):
        if actual != expected:
            raise VerificationError(f"{released_path}.{name} disagrees with its receipt")
    for index, field_name in (
        (15, "client_delivery_evidence_digest_hex"),
        (16, "consumed_authorization_evidence_digest_hex"),
    ):
        evidence = _decode_hex(released[field_name], 32, f"{released_path}.{field_name}")
        _require_nonzero_bytes(evidence, 32, f"{released_path}.{field_name}")
        if released_fields[index] != evidence:
            raise VerificationError(f"{released_path}.{field_name} disagrees with its receipt")
    released_receipt_digest = _digest_encoding(
        EXPORT_RELEASED_RECEIPT_DIGEST_DOMAIN_V1, released_encoding
    )
    _require_expected_bytes(
        released["released_receipt_digest_hex"],
        released_receipt_digest,
        f"{released_path}.released_receipt_digest_hex",
    )
    if released["active_state_version"] != committed["active_state_version"]:
        raise VerificationError(f"{released_path}.active_state_version changed")
    _require_exact_value(
        _require_string(released["authorization_state"], f"{released_path}.authorization_state"),
        "consumed",
        f"{released_path}.authorization_state",
    )
    seed = _decode_hex(released["client_seed_hex"], 32, f"{released_path}.client_seed_hex")
    if _derive_ed25519_public_key_from_seed(seed) != registered_key:
        raise VerificationError(f"{released_path}.client_seed_hex does not derive the registered key")
    _verify_export_delivery_zero_work(
        released["zero_private_evaluation_work"],
        f"{released_path}.zero_private_evaluation_work",
    )

    redelivered_path = "$.cases[0].redelivered"
    redelivered = _require_ordered_keys(
        case["redelivered"], EXPORT_DELIVERY_REDELIVERED_KEY_ORDER, redelivered_path
    )
    for name in ("before_released_receipt_digest_hex", "after_released_receipt_digest_hex"):
        if _decode_hex(redelivered[name], 32, f"{redelivered_path}.{name}") != released_receipt_digest:
            raise VerificationError(f"{redelivered_path}.{name} changed")
    if _decode_hex(redelivered["client_seed_hex"], 32, f"{redelivered_path}.client_seed_hex") != seed:
        raise VerificationError(f"{redelivered_path}.client_seed_hex changed")
    _verify_export_delivery_zero_work(
        redelivered["zero_private_evaluation_work"],
        f"{redelivered_path}.zero_private_evaluation_work",
    )
    return 1


def _verify_activation_delivery_zero_work(value: Any, path: str) -> None:
    counters = _require_ordered_keys(
        value, ACTIVATION_DELIVERY_ZERO_WORK_KEY_ORDER, path
    )
    for name in ACTIVATION_DELIVERY_ZERO_WORK_KEY_ORDER:
        if _require_u8(counters[name], f"{path}.{name}") != 0:
            raise VerificationError(f"{path}.{name} must equal zero")


def _scan_activation_delivery_boundary(value: Any, path: str) -> None:
    forbidden = {
        "signing_worker_scalar_hex",
        "scalar_share_hex",
        "derivation_root_hex",
        "ciphertext_bytes_hex",
        "decryption_key_hex",
        "opener_state_hex",
        "frame_bytes_hex",
    }
    if type(value) is dict:
        for key, nested in value.items():
            if any(name in key for name in forbidden):
                raise VerificationError(f"{path}.{key} is forbidden")
            _scan_activation_delivery_boundary(nested, f"{path}.{key}")
    elif type(value) is list:
        for index, nested in enumerate(value):
            _scan_activation_delivery_boundary(nested, f"{path}[{index}]")


def verify_activation_delivery_corpus(
    corpus: Any,
    semantic_lifecycle_corpus: Any,
    ceremony_context_corpus: Any,
    provenance_corpus: Any,
    output_party_views_corpus: Any,
) -> int:
    """Verifies activation authorization ordering and recipient capabilities."""
    semantic = _verified_semantic_lifecycle_details(
        semantic_lifecycle_corpus, ceremony_context_corpus, provenance_corpus
    )
    verify_output_party_views_corpus(
        output_party_views_corpus,
        semantic_lifecycle_corpus,
        ceremony_context_corpus,
        provenance_corpus,
    )
    document = _require_ordered_keys(
        corpus, ACTIVATION_DELIVERY_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        ACTIVATION_DELIVERY_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    _scan_activation_delivery_boundary(document, "$")
    cases = document["cases"]
    origins = ("registration", "recovery", "refresh")
    case_ids = (
        "registration_activation_delivery_v1",
        "recovery_activation_delivery_v1",
        "refresh_activation_delivery_v1",
    )
    output_party_indices = (0, 2, 3)
    if type(cases) is not list or len(cases) != len(origins):
        raise VerificationError("$.cases must contain exactly three activation-delivery cases")
    output_party_cases = _require_object(
        output_party_views_corpus, "$output_party_views"
    ).get("cases")
    if type(output_party_cases) is not list or len(output_party_cases) != 5:
        raise VerificationError("$output_party_views.cases must contain five cases")

    for index, origin_kind in enumerate(origins):
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], ACTIVATION_DELIVERY_CASE_KEY_ORDER, case_path
        )
        _require_exact_value(
            _require_string(case["case_id"], f"{case_path}.case_id"),
            case_ids[index],
            f"{case_path}.case_id",
        )
        _require_exact_value(
            _require_string(
                case["origin_request_kind"], f"{case_path}.origin_request_kind"
            ),
            origin_kind,
            f"{case_path}.origin_request_kind",
        )
        semantic_origin = semantic["origins"][origin_kind]
        _require_exact_value(
            _require_string(
                case["semantic_lifecycle_case_id"],
                f"{case_path}.semantic_lifecycle_case_id",
            ),
            semantic_origin["case_id"],
            f"{case_path}.semantic_lifecycle_case_id",
        )
        _require_exact_value(
            _require_string(
                case["activation_semantic_lifecycle_case_id"],
                f"{case_path}.activation_semantic_lifecycle_case_id",
            ),
            semantic["activation_control"]["case_id"],
            f"{case_path}.activation_semantic_lifecycle_case_id",
        )

        committed_path = f"{case_path}.output_committed"
        committed = _require_ordered_keys(
            case["output_committed"],
            ACTIVATION_DELIVERY_OUTPUT_COMMITTED_KEY_ORDER,
            committed_path,
        )
        expected_package = semantic_origin["packages"]["package_set_digest"]
        expected_receipt = semantic_origin["receipt"]["receipt_digest"]
        expected_x_client = semantic_origin["receipt"]["x_client"]
        expected_x_server = semantic_origin["receipt"]["x_server"]
        expected_key = semantic_origin["receipt"]["registered_public_key"]
        for field_name, expected in (
            (
                "origin_request_context_digest_hex",
                semantic_origin["ceremony"]["request_digest"],
            ),
            (
                "origin_authorization_digest_hex",
                semantic_origin["ceremony"]["authorization_digest"],
            ),
            (
                "origin_transcript_digest_hex",
                semantic_origin["ceremony"]["transcript_digest"],
            ),
            ("package_set_digest_hex", expected_package),
            ("output_committed_receipt_digest_hex", expected_receipt),
            ("x_client_hex", expected_x_client),
            ("x_server_hex", expected_x_server),
            ("registered_public_key_hex", expected_key),
        ):
            if _decode_hex(
                committed[field_name], 32, f"{committed_path}.{field_name}"
            ) != expected:
                raise VerificationError(f"{committed_path}.{field_name} changed")
        committed_encoding = _decode_variable_hex(
            committed["output_committed_receipt_encoding_hex"],
            f"{committed_path}.output_committed_receipt_encoding_hex",
        )
        if committed_encoding != semantic_origin["receipt"]["encoding"]:
            raise VerificationError(
                f"{committed_path}.output_committed_receipt_encoding_hex changed"
            )
        _require_exact_value(
            _require_string(
                committed["activation_authorization_state"],
                f"{committed_path}.activation_authorization_state",
            ),
            "not_issued",
            f"{committed_path}.activation_authorization_state",
        )

        activation = semantic["activation_control"]["metadata_consumed"][index][
            "activation"
        ]
        admitted_path = f"{case_path}.activation_control_admitted"
        admitted = _require_ordered_keys(
            case["activation_control_admitted"],
            ACTIVATION_DELIVERY_CONTROL_ADMITTED_KEY_ORDER,
            admitted_path,
        )
        metadata_path = f"{case_path}.metadata_consumed"
        metadata = _require_ordered_keys(
            case["metadata_consumed"],
            ACTIVATION_DELIVERY_METADATA_CONSUMED_KEY_ORDER,
            metadata_path,
        )
        activation_values = (
            ("request_context_digest_hex", activation["request_digest"]),
            ("authorization_digest_hex", activation["authorization_digest"]),
            ("transcript_digest_hex", activation["transcript_digest"]),
        )
        for field_name, expected in activation_values:
            for value, path in ((admitted, admitted_path), (metadata, metadata_path)):
                if _decode_hex(value[field_name], 32, f"{path}.{field_name}") != expected:
                    raise VerificationError(f"{path}.{field_name} changed")
        for value, path in ((admitted, admitted_path), (metadata, metadata_path)):
            for field_name, expected in (
                ("package_set_digest_hex", expected_package),
                ("output_committed_receipt_digest_hex", expected_receipt),
            ):
                if _decode_hex(value[field_name], 32, f"{path}.{field_name}") != expected:
                    raise VerificationError(f"{path}.{field_name} changed")
        _require_exact_value(
            _require_string(
                admitted["activation_authorization_state"],
                f"{admitted_path}.activation_authorization_state",
            ),
            "unconsumed",
            f"{admitted_path}.activation_authorization_state",
        )
        _require_exact_value(
            _require_string(
                metadata["activation_authorization_state"],
                f"{metadata_path}.activation_authorization_state",
            ),
            "consumed",
            f"{metadata_path}.activation_authorization_state",
        )
        _verify_activation_delivery_zero_work(
            metadata["zero_private_evaluation_work"],
            f"{metadata_path}.zero_private_evaluation_work",
        )

        uncertain_path = f"{case_path}.delivery_uncertain"
        uncertain = _require_ordered_keys(
            case["delivery_uncertain"],
            ACTIVATION_DELIVERY_UNCERTAIN_KEY_ORDER,
            uncertain_path,
        )
        for field_name in (
            "before_package_set_digest_hex",
            "after_package_set_digest_hex",
        ):
            if _decode_hex(uncertain[field_name], 32, f"{uncertain_path}.{field_name}") != expected_package:
                raise VerificationError(f"{uncertain_path}.{field_name} changed")
        for field_name, expected in (
            ("output_committed_receipt_digest_hex", expected_receipt),
            ("activation_transcript_digest_hex", activation["transcript_digest"]),
        ):
            if _decode_hex(uncertain[field_name], 32, f"{uncertain_path}.{field_name}") != expected:
                raise VerificationError(f"{uncertain_path}.{field_name} changed")

        released_path = f"{case_path}.recipients_released"
        released = _require_ordered_keys(
            case["recipients_released"],
            ACTIVATION_DELIVERY_RELEASED_KEY_ORDER,
            released_path,
        )
        for field_name, expected in (
            ("package_set_digest_hex", expected_package),
            ("output_committed_receipt_digest_hex", expected_receipt),
            ("activation_transcript_digest_hex", activation["transcript_digest"]),
        ):
            if _decode_hex(released[field_name], 32, f"{released_path}.{field_name}") != expected:
                raise VerificationError(f"{released_path}.{field_name} changed")
        client_path = f"{released_path}.client"
        client = _require_ordered_keys(
            released["client"],
            ACTIVATION_DELIVERY_CLIENT_CAPABILITY_KEY_ORDER,
            client_path,
        )
        worker_path = f"{released_path}.signing_worker"
        worker = _require_ordered_keys(
            released["signing_worker"],
            ACTIVATION_DELIVERY_WORKER_CAPABILITY_KEY_ORDER,
            worker_path,
        )
        _require_exact_value(
            _require_string(client["capability_kind"], f"{client_path}.capability_kind"),
            "activation_client_scalar_release",
            f"{client_path}.capability_kind",
        )
        _require_exact_value(
            _require_string(worker["capability_kind"], f"{worker_path}.capability_kind"),
            "signing_worker_activation_release_authority",
            f"{worker_path}.capability_kind",
        )
        for value, path in ((client, client_path), (worker, worker_path)):
            if _decode_hex(value["package_set_digest_hex"], 32, f"{path}.package_set_digest_hex") != expected_package:
                raise VerificationError(f"{path}.package_set_digest_hex changed")
            evidence = _decode_hex(
                value["delivery_evidence_digest_hex"],
                32,
                f"{path}.delivery_evidence_digest_hex",
            )
            _require_nonzero_bytes(evidence, 32, f"{path}.delivery_evidence_digest_hex")

        output_case = output_party_cases[output_party_indices[index]]
        output_vector = _require_object(output_case, "$output_party_case")["vector"]
        output_extensions = _require_object(output_vector, "$output_party_vector")[
            "role_extensions"
        ]
        output_extensions = _require_object(output_extensions, "$output_party_extensions")
        client_a = _decode_scalar(
            _require_object(output_extensions["deriver_a"], "$output_party.deriver_a")[
                "client_scalar_share_hex"
            ],
            "$output_party.deriver_a.client_scalar_share_hex",
        )
        client_b = _decode_scalar(
            _require_object(output_extensions["deriver_b"], "$output_party.deriver_b")[
                "client_scalar_share_hex"
            ],
            "$output_party.deriver_b.client_scalar_share_hex",
        )
        expected_client_scalar = (client_a + client_b) % SCALAR_ORDER
        actual_client_scalar = _decode_scalar(
            client["x_client_base_hex"], f"{client_path}.x_client_base_hex"
        )
        if actual_client_scalar != expected_client_scalar:
            raise VerificationError(f"{client_path}.x_client_base_hex changed")
        if _compress_point(_multiply_base(actual_client_scalar)) != expected_x_client:
            raise VerificationError(f"{client_path}.x_client_base_hex does not match X_client")

        for value, path in (
            (uncertain, uncertain_path),
            (released, released_path),
        ):
            _require_exact_value(
                _require_string(
                    value["activation_authorization_state"],
                    f"{path}.activation_authorization_state",
                ),
                "consumed",
                f"{path}.activation_authorization_state",
            )
            _verify_activation_delivery_zero_work(
                value["zero_private_evaluation_work"],
                f"{path}.zero_private_evaluation_work",
            )

        redelivered_path = f"{case_path}.redelivered"
        redelivered = _require_ordered_keys(
            case["redelivered"],
            ACTIVATION_DELIVERY_REDELIVERED_KEY_ORDER,
            redelivered_path,
        )
        equality_fields = (
            (
                "before_package_set_digest_hex",
                "after_package_set_digest_hex",
                expected_package,
            ),
            (
                "before_client_scalar_hex",
                "after_client_scalar_hex",
                actual_client_scalar.to_bytes(32, "little"),
            ),
            (
                "before_client_delivery_evidence_digest_hex",
                "after_client_delivery_evidence_digest_hex",
                _decode_hex(
                    client["delivery_evidence_digest_hex"],
                    32,
                    f"{client_path}.delivery_evidence_digest_hex",
                ),
            ),
            (
                "before_signing_worker_delivery_evidence_digest_hex",
                "after_signing_worker_delivery_evidence_digest_hex",
                _decode_hex(
                    worker["delivery_evidence_digest_hex"],
                    32,
                    f"{worker_path}.delivery_evidence_digest_hex",
                ),
            ),
            (
                "before_signing_worker_authority_package_set_digest_hex",
                "after_signing_worker_authority_package_set_digest_hex",
                expected_package,
            ),
        )
        for before_name, after_name, expected in equality_fields:
            for field_name in (before_name, after_name):
                if _decode_hex(
                    redelivered[field_name],
                    32,
                    f"{redelivered_path}.{field_name}",
                ) != expected:
                    raise VerificationError(f"{redelivered_path}.{field_name} changed")
        _require_exact_value(
            _require_string(
                redelivered["activation_authorization_state"],
                f"{redelivered_path}.activation_authorization_state",
            ),
            "consumed",
            f"{redelivered_path}.activation_authorization_state",
        )
        _verify_activation_delivery_zero_work(
            redelivered["zero_private_evaluation_work"],
            f"{redelivered_path}.zero_private_evaluation_work",
        )
    return len(cases)


def _verify_strict_ed25519_signature(
    verifying_key: bytes, message: bytes, signature: bytes, path: str
) -> None:
    if len(signature) != 64:
        raise VerificationError(f"{path} must contain exactly 64 bytes")
    public_point = _decompress_point(verifying_key, f"{path}.verifying_key")
    if _points_equal(_multiply_point(public_point, 8), IDENTITY_POINT):
        raise VerificationError(f"{path}.verifying_key must not be weak")
    encoded_r = signature[:32]
    r_point = _decompress_point(encoded_r, f"{path}.R")
    if _points_equal(_multiply_point(r_point, 8), IDENTITY_POINT):
        raise VerificationError(f"{path}.R must not be small order")
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= SCALAR_ORDER:
        raise VerificationError(f"{path}.S must be a canonical Ed25519 scalar")
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + verifying_key + message).digest(), "little"
    ) % SCALAR_ORDER
    left = _multiply_base(scalar_s)
    right = _point_add(r_point, _multiply_point(public_point, challenge))
    if not _points_equal(left, right):
        raise VerificationError(f"{path} is not a strict Ed25519 signature")


def _verify_export_evaluator_acceptance_role(
    role_name: str,
    role_tag: int,
    common: dict[str, Any],
    authority_value: Any,
    acceptance_value: Any,
    path: str,
) -> bytes:
    authority = _require_ordered_keys(
        authority_value,
        EXPORT_EVALUATOR_AUTHORIZATION_AUTHORITY_KEY_ORDER,
        f"{path}.authority",
    )
    _require_exact_value(
        _require_string(authority["role"], f"{path}.authority.role"),
        role_name,
        f"{path}.authority.role",
    )
    deriver_id = _require_string(authority["deriver_id"], f"{path}.authority.deriver_id")
    key_epoch = _require_epoch(authority["key_epoch"], f"{path}.authority.key_epoch")
    verifying_key = _decode_hex(
        authority["verifying_key_hex"], 32, f"{path}.authority.verifying_key_hex"
    )
    expected_fixture_seed = bytes((0x6A if role_tag == 0x01 else 0x6B,)) * 32
    if verifying_key != _derive_ed25519_public_key_from_seed(expected_fixture_seed):
        raise VerificationError(f"{path}.authority.verifying_key_hex is not the pinned fixture key")
    expected_key_digest = hashlib.sha256(
        _lp32_join(
            (
                EXPORT_AUTHORIZATION_ACCEPTANCE_AUTHORITY_KEY_DIGEST_DOMAIN_V1,
                bytes((role_tag,)),
                key_epoch.to_bytes(8, "big"),
                verifying_key,
            )
        )
    ).digest()
    if _decode_hex(authority["key_digest_hex"], 32, f"{path}.authority.key_digest_hex") != expected_key_digest:
        raise VerificationError(f"{path}.authority.key_digest_hex changed")

    acceptance = _require_ordered_keys(
        acceptance_value,
        EXPORT_EVALUATOR_AUTHORIZATION_ACCEPTANCE_KEY_ORDER,
        f"{path}.acceptance",
    )
    _require_exact_value(
        _require_string(acceptance["role"], f"{path}.acceptance.role"),
        role_name,
        f"{path}.acceptance.role",
    )
    checked_at = _require_epoch(
        acceptance["checked_at_unix_ms"], f"{path}.acceptance.checked_at_unix_ms"
    )
    request_expiry = _require_epoch(common["request_expiry_unix_ms"], "$.cases[0].common.request_expiry_unix_ms")
    if checked_at > request_expiry:
        raise VerificationError(f"{path}.acceptance expired")
    statement_digest = _decode_hex(
        acceptance["provenance_statement_digest_hex"],
        32,
        f"{path}.acceptance.provenance_statement_digest_hex",
    )
    signing_bytes = _decode_variable_hex(
        acceptance["signing_bytes_hex"], f"{path}.acceptance.signing_bytes_hex"
    )
    fields = _parse_lp32_fields(
        signing_bytes, 24, f"{path}.acceptance.signing_bytes_hex"
    )
    expected_fields = (
        EXPORT_AUTHORIZATION_ACCEPTANCE_ENCODING_DOMAIN_V1,
        PROTOCOL_ID_V1.encode("ascii"),
        b"\x05",
        bytes((role_tag,)),
        deriver_id.encode("ascii"),
        key_epoch.to_bytes(8, "big"),
        expected_key_digest,
        checked_at.to_bytes(8, "big"),
        _require_string(common["request_id"], "$.cases[0].common.request_id").encode("ascii"),
        _decode_hex(common["replay_nonce_hex"], 32, "$.cases[0].common.replay_nonce_hex"),
        request_expiry.to_bytes(8, "big"),
        _decode_hex(common["client_recipient_key_hex"], 32, "$.cases[0].common.client_recipient_key_hex"),
        _decode_hex(common["request_context_digest_hex"], 32, "$.cases[0].common.request_context_digest_hex"),
        _decode_hex(common["authorization_digest_hex"], 32, "$.cases[0].common.authorization_digest_hex"),
        _decode_hex(common["transcript_digest_hex"], 32, "$.cases[0].common.transcript_digest_hex"),
        _decode_hex(common["provenance_pair_digest_hex"], 32, "$.cases[0].common.provenance_pair_digest_hex"),
        _require_nonzero_bytes(_decode_hex(common["signed_store_resolution_digest_hex"], 32, "$.cases[0].common.signed_store_resolution_digest_hex"), 32, "$.cases[0].common.signed_store_resolution_digest_hex"),
        _require_epoch(common["store_authority_key_epoch"], "$.cases[0].common.store_authority_key_epoch").to_bytes(8, "big"),
        _decode_hex(common["store_authority_key_digest_hex"], 32, "$.cases[0].common.store_authority_key_digest_hex"),
        _require_epoch(common["active_state_version"], "$.cases[0].common.active_state_version").to_bytes(8, "big"),
        _decode_hex(common["registered_public_key_hex"], 32, "$.cases[0].common.registered_public_key_hex"),
        _require_nonzero_bytes(_decode_hex(common["one_use_execution_id_hex"], 32, "$.cases[0].common.one_use_execution_id_hex"), 32, "$.cases[0].common.one_use_execution_id_hex"),
        statement_digest,
        b"\x01",
    )
    if fields != expected_fields:
        raise VerificationError(f"{path}.acceptance.signing_bytes_hex changed")
    signature = _decode_hex(
        acceptance["signature_hex"], 64, f"{path}.acceptance.signature_hex"
    )
    _verify_strict_ed25519_signature(
        verifying_key, signing_bytes, signature, f"{path}.acceptance.signature_hex"
    )
    expected_artifact_digest = hashlib.sha256(
        _lp32_join(
            (
                EXPORT_AUTHORIZATION_ACCEPTANCE_DIGEST_DOMAIN_V1,
                signing_bytes,
                signature,
            )
        )
    ).digest()
    if _decode_hex(acceptance["signed_artifact_digest_hex"], 32, f"{path}.acceptance.signed_artifact_digest_hex") != expected_artifact_digest:
        raise VerificationError(f"{path}.acceptance.signed_artifact_digest_hex changed")
    return expected_artifact_digest


def verify_export_evaluator_authorization_corpus(corpus: Any) -> int:
    document = _require_ordered_keys(
        corpus, EXPORT_EVALUATOR_AUTHORIZATION_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = _require_list(document["cases"], "$.cases")
    if len(cases) != 1:
        raise VerificationError("$.cases must contain exactly one export evaluator case")
    case = _require_ordered_keys(
        cases[0], EXPORT_EVALUATOR_AUTHORIZATION_CASE_KEY_ORDER, "$.cases[0]"
    )
    _require_exact_value(_require_string(case["case_id"], "$.cases[0].case_id"), "export_authorized_evaluation_released_v1", "$.cases[0].case_id")
    _require_exact_value(_require_string(case["request_kind"], "$.cases[0].request_kind"), "export", "$.cases[0].request_kind")
    sources = _require_ordered_keys(case["source_references"], EXPORT_EVALUATOR_AUTHORIZATION_SOURCE_KEY_ORDER, "$.cases[0].source_references")
    expected_sources = (
        ("ceremony_context_case_id", "ceremony-export-v1"),
        ("provenance_case_id", "export_provenance_outer_v1"),
        ("evaluation_input_party_view_case_id", "export_evaluation_input_party_views_v1"),
        ("semantic_lifecycle_case_id", "export_semantic_artifacts_host_reference_receipt_v1"),
        ("export_delivery_case_id", "export_output_commit_release_redelivery_v1"),
    )
    for name, expected in expected_sources:
        _require_exact_value(_require_string(sources[name], f"$.cases[0].source_references.{name}"), expected, f"$.cases[0].source_references.{name}")
    common = _require_ordered_keys(case["common"], EXPORT_EVALUATOR_AUTHORIZATION_COMMON_KEY_ORDER, "$.cases[0].common")
    authorities = _require_ordered_keys(case["authorities"], EXPORT_EVALUATOR_AUTHORIZATION_AUTHORITIES_KEY_ORDER, "$.cases[0].authorities")
    acceptances = _require_ordered_keys(case["acceptances"], EXPORT_EVALUATOR_AUTHORIZATION_ACCEPTANCES_KEY_ORDER, "$.cases[0].acceptances")
    a_digest = _verify_export_evaluator_acceptance_role("deriver_a", 0x01, common, authorities["deriver_a"], acceptances["deriver_a"], "$.cases[0].deriver_a")
    b_digest = _verify_export_evaluator_acceptance_role("deriver_b", 0x02, common, authorities["deriver_b"], acceptances["deriver_b"], "$.cases[0].deriver_b")
    if _decode_hex(authorities["deriver_a"]["verifying_key_hex"], 32, "$.cases[0].authorities.deriver_a.verifying_key_hex") == _decode_hex(authorities["deriver_b"]["verifying_key_hex"], 32, "$.cases[0].authorities.deriver_b.verifying_key_hex"):
        raise VerificationError("$.cases[0].authorities must use distinct role keys")
    pair = _require_ordered_keys(case["accepted_pair"], EXPORT_EVALUATOR_AUTHORIZATION_PAIR_KEY_ORDER, "$.cases[0].accepted_pair")
    pair_encoding = _decode_variable_hex(pair["encoding_hex"], "$.cases[0].accepted_pair.encoding_hex")
    if _parse_lp32_fields(pair_encoding, 3, "$.cases[0].accepted_pair.encoding_hex") != (EXPORT_AUTHORIZATION_ACCEPTANCE_PAIR_ENCODING_DOMAIN_V1, a_digest, b_digest):
        raise VerificationError("$.cases[0].accepted_pair.encoding_hex changed")
    pair_digest = hashlib.sha256(_lp32_join((EXPORT_AUTHORIZATION_ACCEPTANCE_PAIR_DIGEST_DOMAIN_V1, pair_encoding))).digest()
    if _decode_hex(pair["digest_hex"], 32, "$.cases[0].accepted_pair.digest_hex") != pair_digest:
        raise VerificationError("$.cases[0].accepted_pair.digest_hex changed")
    evaluation = _require_ordered_keys(case["evaluation"], EXPORT_EVALUATOR_AUTHORIZATION_EVALUATION_KEY_ORDER, "$.cases[0].evaluation")
    _require_exact_value(_require_string(evaluation["evaluation_plan"], "$.cases[0].evaluation.evaluation_plan"), "one_export_evaluation", "$.cases[0].evaluation.evaluation_plan")
    for name in ("yao_evaluations", "deriver_a_invocations", "deriver_b_invocations"):
        if type(evaluation[name]) is not int or evaluation[name] != 1:
            raise VerificationError(f"$.cases[0].evaluation.{name} must equal 1")
    _require_exact_value(_require_string(evaluation["output_committed_authorization_state"], "$.cases[0].evaluation.output_committed_authorization_state"), "unconsumed", "$.cases[0].evaluation.output_committed_authorization_state")
    _require_exact_value(_require_string(evaluation["released_authorization_state"], "$.cases[0].evaluation.released_authorization_state"), "consumed", "$.cases[0].evaluation.released_authorization_state")
    committed_path = "$.cases[0].evaluation.output_committed_receipt_encoding_hex"
    committed_encoding = _decode_variable_hex(
        evaluation["output_committed_receipt_encoding_hex"], committed_path
    )
    committed_fields = _parse_lp32_fields(committed_encoding, 16, committed_path)
    if committed_fields[0] != EXPORT_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1:
        raise VerificationError(f"{committed_path} has the wrong domain")
    if committed_fields[1:4] != (b"\x01", b"\x01", b"\x05"):
        raise VerificationError(f"{committed_path} has invalid tags")
    for actual, expected, name in (
        (committed_fields[4], _decode_hex(common["request_context_digest_hex"], 32, "$.cases[0].common.request_context_digest_hex"), "request_context_digest"),
        (committed_fields[5], _decode_hex(common["authorization_digest_hex"], 32, "$.cases[0].common.authorization_digest_hex"), "authorization_digest"),
        (committed_fields[6], _decode_hex(common["transcript_digest_hex"], 32, "$.cases[0].common.transcript_digest_hex"), "transcript_digest"),
        (committed_fields[9], _decode_hex(common["one_use_execution_id_hex"], 32, "$.cases[0].common.one_use_execution_id_hex"), "one_use_execution_id"),
        (committed_fields[10], _decode_hex(common["provenance_pair_digest_hex"], 32, "$.cases[0].common.provenance_pair_digest_hex"), "provenance_pair_digest"),
        (committed_fields[11], pair_digest, "acceptance_pair_digest"),
        (committed_fields[13], _decode_hex(common["registered_public_key_hex"], 32, "$.cases[0].common.registered_public_key_hex"), "registered_public_key"),
    ):
        if actual != expected:
            raise VerificationError(f"{committed_path} changed {name}")
    for index in (7, 8, 12, 14, 15):
        _require_nonzero_bytes(committed_fields[index], 32, f"{committed_path}[{index}]")
    committed_receipt_digest = _digest_encoding(
        EXPORT_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1, committed_encoding
    )
    _require_expected_bytes(
        evaluation["output_committed_receipt_digest_hex"],
        committed_receipt_digest,
        "$.cases[0].evaluation.output_committed_receipt_digest_hex",
    )
    released_path = "$.cases[0].evaluation.released_receipt_encoding_hex"
    released_encoding = _decode_variable_hex(
        evaluation["released_receipt_encoding_hex"], released_path
    )
    released_fields = _parse_lp32_fields(released_encoding, 17, released_path)
    if released_fields[0] != EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1:
        raise VerificationError(f"{released_path} has the wrong domain")
    if released_fields[1:4] != (b"\x02", b"\x02", b"\x05"):
        raise VerificationError(f"{released_path} has invalid tags")
    for index in range(4, 14):
        if released_fields[index] != committed_fields[index]:
            raise VerificationError(f"{released_path} changed committed field {index}")
    if released_fields[14] != committed_receipt_digest:
        raise VerificationError(f"{released_path} changed the committed receipt digest")
    for index in (15, 16):
        _require_nonzero_bytes(released_fields[index], 32, f"{released_path}[{index}]")
    released_receipt_digest = _digest_encoding(
        EXPORT_RELEASED_RECEIPT_DIGEST_DOMAIN_V1, released_encoding
    )
    _require_expected_bytes(
        evaluation["released_receipt_digest_hex"],
        released_receipt_digest,
        "$.cases[0].evaluation.released_receipt_digest_hex",
    )
    for name in ("output_committed_evaluation_evidence_digest_hex", "released_evaluation_evidence_digest_hex"):
        if _decode_hex(evaluation[name], 32, f"$.cases[0].evaluation.{name}") != pair_digest:
            raise VerificationError(f"$.cases[0].evaluation.{name} changed")
    if evaluation["registered_state_retained"] is not True:
        raise VerificationError("$.cases[0].evaluation.registered_state_retained must be true")
    forbidden = {"tau", "joined_seed", "seed_hex", "signing_worker_output", "generic_evidence"}
    def scan(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if any(fragment in key for fragment in forbidden):
                    raise VerificationError(f"{path}.{key} is forbidden")
                scan(nested, f"{path}.{key}")
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                scan(nested, f"{path}[{index}]")
    scan(document, "$")
    return 1


def _registration_role_state_fields(
    value: Any, expected_role: str, path: str
) -> tuple[bytes, ...]:
    state = _require_ordered_keys(
        value, REGISTRATION_EVALUATOR_ADMISSION_ROLE_STATE_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(state["role"], f"{path}.role"),
        expected_role,
        f"{path}.role",
    )
    return (
        _require_nonzero_bytes(
            _decode_hex(
                state["role_root_record_digest_hex"],
                32,
                f"{path}.role_root_record_digest_hex",
            ),
            32,
            f"{path}.role_root_record_digest_hex",
        ),
        _require_nonzero_bytes(
            _decode_hex(
                state["root_binding_artifact_digest_hex"],
                32,
                f"{path}.root_binding_artifact_digest_hex",
            ),
            32,
            f"{path}.root_binding_artifact_digest_hex",
        ),
        _require_epoch(state["role_root_epoch"], f"{path}.role_root_epoch").to_bytes(
            8, "big"
        ),
        _require_nonzero_bytes(
            _decode_hex(
                state["input_state_record_digest_hex"],
                32,
                f"{path}.input_state_record_digest_hex",
            ),
            32,
            f"{path}.input_state_record_digest_hex",
        ),
        _require_epoch(
            state["input_state_epoch"], f"{path}.input_state_epoch"
        ).to_bytes(8, "big"),
    )


def verify_registration_evaluator_admission_corpus(corpus: Any) -> int:
    document = _require_ordered_keys(
        corpus, REGISTRATION_EVALUATOR_ADMISSION_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        REGISTRATION_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        REGISTRATION_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = _require_list(document["cases"], "$.cases")
    if len(cases) != 1:
        raise VerificationError(
            "$.cases must contain exactly one registration evaluator case"
        )
    case = _require_ordered_keys(
        cases[0], REGISTRATION_EVALUATOR_ADMISSION_CASE_KEY_ORDER, "$.cases[0]"
    )
    _require_exact_value(
        _require_string(case["case_id"], "$.cases[0].case_id"),
        "registration_admitted_evaluation_output_committed_v1",
        "$.cases[0].case_id",
    )
    _require_exact_value(
        _require_string(case["request_kind"], "$.cases[0].request_kind"),
        "registration",
        "$.cases[0].request_kind",
    )
    sources = _require_ordered_keys(
        case["source_references"],
        REGISTRATION_EVALUATOR_ADMISSION_SOURCE_KEY_ORDER,
        "$.cases[0].source_references",
    )
    expected_sources = (
        ("ceremony_context_case_id", "ceremony-registration-v1"),
        ("provenance_case_id", "registration_provenance_outer_v1"),
        (
            "evaluation_input_party_view_case_id",
            "registration_evaluation_input_party_views_v1",
        ),
        (
            "semantic_lifecycle_case_id",
            "registration_semantic_artifacts_output_committed_v1",
        ),
        (
            "output_party_view_case_id",
            "registration_output_party_views_package_prepared_v1",
        ),
        ("activation_delivery_case_id", "registration_activation_delivery_v1"),
        (
            "activation_recipient_party_view_case_id",
            "registration_activation_recipient_party_views_v1",
        ),
        (
            "evaluator_abort_corpus_schema",
            EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1,
        ),
        ("evaluator_abort_request_kind", "registration"),
    )
    for name, expected in expected_sources:
        _require_exact_value(
            _require_string(
                sources[name], f"$.cases[0].source_references.{name}"
            ),
            expected,
            f"$.cases[0].source_references.{name}",
        )

    admission = _require_ordered_keys(
        case["admission"],
        REGISTRATION_EVALUATOR_ADMISSION_KEY_ORDER,
        "$.cases[0].admission",
    )
    _require_exact_value(
        _require_string(admission["relation"], "$.cases[0].admission.relation"),
        "construction_independent_ideal_acceptance",
        "$.cases[0].admission.relation",
    )
    identity_scope = _decode_variable_hex(
        admission["unregistered_public_identity_scope_encoding_hex"],
        "$.cases[0].admission.unregistered_public_identity_scope_encoding_hex",
    )
    identity_fields = _parse_lp32_fields(
        identity_scope,
        13,
        "$.cases[0].admission.unregistered_public_identity_scope_encoding_hex",
    )
    if identity_fields[0] != STORE_IDENTITY_SCOPE_DOMAIN_V1:
        raise VerificationError(
            "$.cases[0].admission.unregistered_public_identity_scope_encoding_hex has the wrong domain"
        )
    expected_identity_labels = (
        b"walletId",
        b"organizationId",
        b"projectId",
        b"environmentId",
        b"signingRootId",
        b"chainTarget",
    )
    for index, label in enumerate(expected_identity_labels):
        if identity_fields[1 + 2 * index] != label:
            raise VerificationError(
                "$.cases[0].admission.unregistered_public_identity_scope_encoding_hex changed labels"
            )
        if not identity_fields[2 + 2 * index]:
            raise VerificationError(
                "$.cases[0].admission.unregistered_public_identity_scope_encoding_hex has an empty value"
            )
    request_id = _require_string(
        admission["request_id"], "$.cases[0].admission.request_id"
    ).encode("ascii")
    replay_nonce = _decode_hex(
        admission["replay_nonce_hex"],
        32,
        "$.cases[0].admission.replay_nonce_hex",
    )
    request_expiry = _require_epoch(
        admission["request_expiry_unix_ms"],
        "$.cases[0].admission.request_expiry_unix_ms",
    )
    checked_at = _require_epoch(
        admission["checked_at_unix_ms"],
        "$.cases[0].admission.checked_at_unix_ms",
    )
    if checked_at > request_expiry:
        raise VerificationError("$.cases[0].admission is expired")
    request_context_digest = _decode_hex(
        admission["request_context_digest_hex"],
        32,
        "$.cases[0].admission.request_context_digest_hex",
    )
    _require_nonzero_bytes(
        _decode_hex(
            admission["authorization_record_digest_hex"],
            32,
            "$.cases[0].admission.authorization_record_digest_hex",
        ),
        32,
        "$.cases[0].admission.authorization_record_digest_hex",
    )
    authorization_digest = _decode_hex(
        admission["authorization_digest_hex"],
        32,
        "$.cases[0].admission.authorization_digest_hex",
    )
    transcript_digest = _decode_hex(
        admission["transcript_digest_hex"],
        32,
        "$.cases[0].admission.transcript_digest_hex",
    )
    registration_intent = _require_nonzero_bytes(
        _decode_hex(
            admission["registration_intent_digest_hex"],
            32,
            "$.cases[0].admission.registration_intent_digest_hex",
        ),
        32,
        "$.cases[0].admission.registration_intent_digest_hex",
    )
    provenance_pair_digest = _decode_hex(
        admission["provenance_pair_digest_hex"],
        32,
        "$.cases[0].admission.provenance_pair_digest_hex",
    )
    deriver_a_statement_digest = _decode_hex(
        admission["deriver_a_statement_digest_hex"],
        32,
        "$.cases[0].admission.deriver_a_statement_digest_hex",
    )
    deriver_b_statement_digest = _decode_hex(
        admission["deriver_b_statement_digest_hex"],
        32,
        "$.cases[0].admission.deriver_b_statement_digest_hex",
    )
    stable_scope = _decode_variable_hex(
        admission["stable_scope_encoding_hex"],
        "$.cases[0].admission.stable_scope_encoding_hex",
    )
    stable_fields = _parse_lp32_fields(
        stable_scope, 5, "$.cases[0].admission.stable_scope_encoding_hex"
    )
    if stable_fields[0] != PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1:
        raise VerificationError(
            "$.cases[0].admission.stable_scope_encoding_hex has the wrong domain"
        )
    _require_nonzero_bytes(
        stable_fields[1], 32, "$.cases[0].admission.stable_scope.application"
    )
    participant_a = int.from_bytes(
        _require_fixed_bytes(
            stable_fields[2], 2, "$.cases[0].admission.stable_scope.participant_a"
        ),
        "big",
    )
    participant_b = int.from_bytes(
        _require_fixed_bytes(
            stable_fields[3], 2, "$.cases[0].admission.stable_scope.participant_b"
        ),
        "big",
    )
    if participant_a == 0 or participant_a >= participant_b:
        raise VerificationError(
            "$.cases[0].admission.stable_scope participants are noncanonical"
        )
    _require_nonzero_bytes(
        stable_fields[4], 32, "$.cases[0].admission.stable_scope.binding"
    )
    provenance_selection_artifact = _require_nonzero_bytes(
        _decode_hex(
            admission["provenance_input_selection_artifact_digest_hex"],
            32,
            "$.cases[0].admission.provenance_input_selection_artifact_digest_hex",
        ),
        32,
        "$.cases[0].admission.provenance_input_selection_artifact_digest_hex",
    )
    selected_mechanism_evidence = _require_nonzero_bytes(
        _decode_hex(
            admission["selected_mechanism_acceptance_evidence_digest_hex"],
            32,
            "$.cases[0].admission.selected_mechanism_acceptance_evidence_digest_hex",
        ),
        32,
        "$.cases[0].admission.selected_mechanism_acceptance_evidence_digest_hex",
    )
    client_envelope_set = _require_nonzero_bytes(
        _decode_hex(
            admission["client_envelope_set_digest_hex"],
            32,
            "$.cases[0].admission.client_envelope_set_digest_hex",
        ),
        32,
        "$.cases[0].admission.client_envelope_set_digest_hex",
    )
    deriver_a_state = _registration_role_state_fields(
        admission["deriver_a_initial_state"],
        "deriver_a",
        "$.cases[0].admission.deriver_a_initial_state",
    )
    deriver_b_state = _registration_role_state_fields(
        admission["deriver_b_initial_state"],
        "deriver_b",
        "$.cases[0].admission.deriver_b_initial_state",
    )
    activation_epoch = _require_epoch(
        admission["activation_epoch"], "$.cases[0].admission.activation_epoch"
    )
    execution_id = _require_nonzero_bytes(
        _decode_hex(
            admission["one_use_execution_id_hex"],
            32,
            "$.cases[0].admission.one_use_execution_id_hex",
        ),
        32,
        "$.cases[0].admission.one_use_execution_id_hex",
    )
    selection_attempt = _require_nonzero_bytes(
        _decode_hex(
            admission["selection_attempt_id_hex"],
            32,
            "$.cases[0].admission.selection_attempt_id_hex",
        ),
        32,
        "$.cases[0].admission.selection_attempt_id_hex",
    )
    _require_exact_value(
        _require_string(
            admission["selection_state"], "$.cases[0].admission.selection_state"
        ),
        "accepted_terminal",
        "$.cases[0].admission.selection_state",
    )
    common_fields = (
        identity_scope,
        request_id,
        replay_nonce,
        request_expiry.to_bytes(8, "big"),
        checked_at.to_bytes(8, "big"),
        request_context_digest,
        authorization_digest,
        transcript_digest,
        registration_intent,
        provenance_pair_digest,
        deriver_a_statement_digest,
        deriver_b_statement_digest,
        stable_scope,
        provenance_selection_artifact,
        client_envelope_set,
    ) + deriver_a_state + deriver_b_state + (
        activation_epoch.to_bytes(8, "big"),
        execution_id,
    )
    admission_fields = (
        REGISTRATION_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1,
    ) + common_fields + (
        selection_attempt,
        selected_mechanism_evidence,
        b"\x01",
    )
    admission_encoding = _decode_variable_hex(
        admission["encoding_hex"], "$.cases[0].admission.encoding_hex"
    )
    if _parse_lp32_fields(
        admission_encoding,
        len(admission_fields),
        "$.cases[0].admission.encoding_hex",
    ) != admission_fields:
        raise VerificationError("$.cases[0].admission.encoding_hex changed")
    admission_digest = _digest_encoding(
        REGISTRATION_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1, admission_encoding
    )
    _require_expected_bytes(
        admission["digest_hex"],
        admission_digest,
        "$.cases[0].admission.digest_hex",
    )

    evaluation = _require_ordered_keys(
        case["evaluation"],
        REGISTRATION_EVALUATOR_ADMISSION_EVALUATION_KEY_ORDER,
        "$.cases[0].evaluation",
    )
    _require_exact_value(
        _require_string(
            evaluation["evaluation_plan"], "$.cases[0].evaluation.evaluation_plan"
        ),
        "one_registration_evaluation",
        "$.cases[0].evaluation.evaluation_plan",
    )
    expected_counts = {
        "yao_evaluations": 1,
        "deriver_a_invocations": 1,
        "deriver_b_invocations": 1,
        "contribution_derivations": 0,
        "output_share_samples": 2,
    }
    for name, expected in expected_counts.items():
        if type(evaluation[name]) is not int or evaluation[name] != expected:
            raise VerificationError(
                f"$.cases[0].evaluation.{name} must equal {expected}"
            )
    registered_public_key = _require_nonzero_bytes(
        _decode_hex(
            evaluation["registered_public_key_hex"],
            32,
            "$.cases[0].evaluation.registered_public_key_hex",
        ),
        32,
        "$.cases[0].evaluation.registered_public_key_hex",
    )
    package_set_digest = _require_nonzero_bytes(
        _decode_hex(
            evaluation["package_set_digest_hex"],
            32,
            "$.cases[0].evaluation.package_set_digest_hex",
        ),
        32,
        "$.cases[0].evaluation.package_set_digest_hex",
    )
    receipt_path = "$.cases[0].evaluation.output_committed_receipt_encoding_hex"
    receipt_encoding = _decode_variable_hex(
        evaluation["output_committed_receipt_encoding_hex"], receipt_path
    )
    receipt_fields = _parse_lp32_fields(receipt_encoding, 19, receipt_path)
    if receipt_fields[0] != ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1:
        raise VerificationError(f"{receipt_path} has the wrong domain")
    if receipt_fields[1:4] != (b"\x01", b"\x01", b"\x01"):
        raise VerificationError(f"{receipt_path} has invalid tags")
    expected_receipt_bindings = (
        (4, request_context_digest, "request context"),
        (5, authorization_digest, "authorization"),
        (6, transcript_digest, "transcript"),
        (9, execution_id, "execution"),
        (10, provenance_pair_digest, "provenance"),
        (11, admission_digest, "admission"),
        (12, activation_epoch.to_bytes(8, "big"), "activation epoch"),
        (13, package_set_digest, "package set"),
        (16, registered_public_key, "registered public key"),
    )
    for index, expected, name in expected_receipt_bindings:
        if receipt_fields[index] != expected:
            raise VerificationError(f"{receipt_path} changed {name}")
    for index in (7, 8, 14, 15, 17, 18):
        _require_nonzero_bytes(receipt_fields[index], 32, f"{receipt_path}[{index}]")
    _require_activation_public_relation(
        receipt_fields[14], receipt_fields[15], registered_public_key, receipt_path
    )
    receipt_digest = _digest_encoding(
        ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1, receipt_encoding
    )
    _require_expected_bytes(
        evaluation["output_committed_receipt_digest_hex"],
        receipt_digest,
        "$.cases[0].evaluation.output_committed_receipt_digest_hex",
    )
    _require_expected_bytes(
        evaluation["output_committed_evaluation_evidence_digest_hex"],
        admission_digest,
        "$.cases[0].evaluation.output_committed_evaluation_evidence_digest_hex",
    )
    candidate_fields = (
        REGISTRATION_CANDIDATE_STATE_ENCODING_DOMAIN_V1,
    ) + common_fields + (
        selection_attempt,
        selected_mechanism_evidence,
        admission_digest,
        registered_public_key,
        receipt_digest,
    )
    candidate_encoding = _decode_variable_hex(
        evaluation["candidate_encoding_hex"],
        "$.cases[0].evaluation.candidate_encoding_hex",
    )
    if _parse_lp32_fields(
        candidate_encoding,
        len(candidate_fields),
        "$.cases[0].evaluation.candidate_encoding_hex",
    ) != candidate_fields:
        raise VerificationError("$.cases[0].evaluation.candidate_encoding_hex changed")
    candidate_digest = _digest_encoding(
        REGISTRATION_CANDIDATE_STATE_DIGEST_DOMAIN_V1, candidate_encoding
    )
    _require_expected_bytes(
        evaluation["candidate_digest_hex"],
        candidate_digest,
        "$.cases[0].evaluation.candidate_digest_hex",
    )
    _require_expected_bytes(
        evaluation["candidate_output_committed_receipt_digest_hex"],
        receipt_digest,
        "$.cases[0].evaluation.candidate_output_committed_receipt_digest_hex",
    )
    _require_exact_value(
        _require_string(
            evaluation["pending_state"], "$.cases[0].evaluation.pending_state"
        ),
        "registration_pending_activation",
        "$.cases[0].evaluation.pending_state",
    )
    if evaluation["terminal_selection_retained"] is not True:
        raise VerificationError(
            "$.cases[0].evaluation.terminal_selection_retained must be true"
        )

    retry = _require_ordered_keys(
        case["retry"],
        REGISTRATION_EVALUATOR_ADMISSION_RETRY_KEY_ORDER,
        "$.cases[0].retry",
    )
    for name in (
        "accepted_selection_is_terminal",
        "evaluator_abort_retains_terminal_selection",
        "retry_requires_fresh_execution",
    ):
        if retry[name] is not True:
            raise VerificationError(f"$.cases[0].retry.{name} must be true")
    if retry["retry_may_resample_selection"] is not False:
        raise VerificationError(
            "$.cases[0].retry.retry_may_resample_selection must be false"
        )
    _require_exact_value(
        _require_string(
            retry["evaluator_abort_preserves_public_state"],
            "$.cases[0].retry.evaluator_abort_preserves_public_state",
        ),
        "unregistered",
        "$.cases[0].retry.evaluator_abort_preserves_public_state",
    )
    claim_boundary = _require_ordered_keys(
        case["claim_boundary"],
        REGISTRATION_EVALUATOR_ADMISSION_CLAIM_BOUNDARY_KEY_ORDER,
        "$.cases[0].claim_boundary",
    )
    expected_claims = (
        ("unregistered_scope_claim", "public_identity_scope_only"),
        (
            "provenance_input_selection_artifact_semantics",
            "opaque_artifact_committed_by_both_provenance_statements",
        ),
        (
            "selected_mechanism_acceptance_evidence_semantics",
            "opaque_acceptance_slot_instantiated_by_phase_6b",
        ),
    )
    for name, expected in expected_claims:
        _require_exact_value(
            _require_string(
                claim_boundary[name], f"$.cases[0].claim_boundary.{name}"
            ),
            expected,
            f"$.cases[0].claim_boundary.{name}",
        )
    excluded_claims = _require_list(
        claim_boundary["excluded_claims"],
        "$.cases[0].claim_boundary.excluded_claims",
    )
    expected_excluded_claims = [
        "authenticated_absence",
        "durable_uniqueness",
        "retry_coordination",
        "profile_security",
        "signature_unforgeability",
        "input_opening_consistency",
        "production_randomness",
        "transport_security",
        "production_constant_time",
    ]
    if excluded_claims != expected_excluded_claims:
        raise VerificationError(
            "$.cases[0].claim_boundary.excluded_claims changed"
        )

    forbidden_keys = {
        "signature_hex",
        "proof_hex",
        "security_profile",
        "seed_output_hex",
        "frame_bytes_hex",
        "durable_reservation",
    }

    def scan(value: Any, path: str) -> None:
        if type(value) is dict:
            for key, nested in value.items():
                if key in forbidden_keys:
                    raise VerificationError(f"{path}.{key} is forbidden")
                scan(nested, f"{path}.{key}")
        elif type(value) is list:
            for index, nested in enumerate(value):
                scan(nested, f"{path}[{index}]")

    scan(document, "$")
    return 1


def verify_recovery_evaluator_admission_corpus(corpus: Any) -> int:
    document = _require_ordered_keys(
        corpus, RECOVERY_EVALUATOR_ADMISSION_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        RECOVERY_EVALUATOR_ADMISSION_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = _require_list(document["cases"], "$.cases")
    if len(cases) != 1:
        raise VerificationError("$.cases must contain exactly one recovery evaluator case")
    case = _require_ordered_keys(
        cases[0], RECOVERY_EVALUATOR_ADMISSION_CASE_KEY_ORDER, "$.cases[0]"
    )
    _require_exact_value(
        _require_string(case["case_id"], "$.cases[0].case_id"),
        "recovery_admitted_evaluation_output_committed_v1",
        "$.cases[0].case_id",
    )
    _require_exact_value(
        _require_string(case["request_kind"], "$.cases[0].request_kind"),
        "recovery",
        "$.cases[0].request_kind",
    )
    sources = _require_ordered_keys(
        case["source_references"],
        RECOVERY_EVALUATOR_ADMISSION_SOURCE_KEY_ORDER,
        "$.cases[0].source_references",
    )
    expected_sources = (
        ("ceremony_context_case_id", "ceremony-recovery-v1"),
        ("provenance_case_id", "recovery_provenance_outer_v1"),
        ("evaluation_input_party_view_case_id", "recovery_evaluation_input_party_views_v1"),
        ("semantic_lifecycle_case_id", "recovery_semantic_artifacts_output_committed_v1"),
        ("output_party_view_case_id", "recovery_output_party_views_package_prepared_v1"),
        ("activation_delivery_case_id", "recovery_activation_delivery_v1"),
        ("activation_recipient_party_view_case_id", "recovery_activation_recipient_party_views_v1"),
        ("recovery_credential_transition_case_id", "recovery_credential_suspension_promotion_v1"),
        ("evaluator_abort_corpus_schema", EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1),
        ("evaluator_abort_request_kind", "recovery"),
    )
    for name, expected in expected_sources:
        _require_exact_value(
            _require_string(sources[name], f"$.cases[0].source_references.{name}"),
            expected,
            f"$.cases[0].source_references.{name}",
        )

    store = _require_ordered_keys(
        case["authenticated_store_resolution"],
        RECOVERY_EVALUATOR_STORE_KEY_ORDER,
        "$.cases[0].authenticated_store_resolution",
    )
    authority_epoch = _require_epoch(
        store["authority_key_epoch"],
        "$.cases[0].authenticated_store_resolution.authority_key_epoch",
    )
    authority_verifying_key = _decode_hex(
        store["authority_verifying_key_hex"],
        32,
        "$.cases[0].authenticated_store_resolution.authority_verifying_key_hex",
    )
    authority_digest = _require_nonzero_bytes(
        _decode_hex(
            store["authority_key_digest_hex"],
            32,
            "$.cases[0].authenticated_store_resolution.authority_key_digest_hex",
        ),
        32,
        "$.cases[0].authenticated_store_resolution.authority_key_digest_hex",
    )
    active_state_version = _require_epoch(
        store["active_state_version"],
        "$.cases[0].authenticated_store_resolution.active_state_version",
    )
    registered_public_key = _require_nonzero_bytes(
        _decode_hex(store["registered_public_key_hex"], 32, "$.cases[0].authenticated_store_resolution.registered_public_key_hex"),
        32,
        "$.cases[0].authenticated_store_resolution.registered_public_key_hex",
    )
    active_credential = _require_nonzero_bytes(
        _decode_hex(store["active_credential_binding_digest_hex"], 32, "$.cases[0].authenticated_store_resolution.active_credential_binding_digest_hex"),
        32,
        "$.cases[0].authenticated_store_resolution.active_credential_binding_digest_hex",
    )
    stable_scope = _decode_variable_hex(
        store["stable_scope_encoding_hex"],
        "$.cases[0].authenticated_store_resolution.stable_scope_encoding_hex",
    )
    stable_fields = _parse_lp32_fields(
        stable_scope,
        5,
        "$.cases[0].authenticated_store_resolution.stable_scope_encoding_hex",
    )
    if stable_fields[0] != PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1:
        raise VerificationError("recovery evaluator stable scope has the wrong domain")
    current_epoch = _require_epoch(
        store["active_activation_epoch"],
        "$.cases[0].authenticated_store_resolution.active_activation_epoch",
    )
    role_fields: list[bytes] = []
    for role in ("deriver_a", "deriver_b"):
        role_fields.extend(
            (
                _require_nonzero_bytes(_decode_hex(store[f"{role}_root_record_digest_hex"], 32, f"store.{role}_root_record"), 32, f"store.{role}_root_record"),
                _require_nonzero_bytes(_decode_hex(store[f"{role}_root_binding_artifact_digest_hex"], 32, f"store.{role}_root_binding"), 32, f"store.{role}_root_binding"),
                _require_epoch(store[f"{role}_root_epoch"], f"store.{role}_root_epoch").to_bytes(8, "big"),
                _require_nonzero_bytes(_decode_hex(store[f"{role}_input_state_record_digest_hex"], 32, f"store.{role}_state_record"), 32, f"store.{role}_state_record"),
                _require_epoch(store[f"{role}_input_state_epoch"], f"store.{role}_state_epoch").to_bytes(8, "big"),
            )
        )

    admission = _require_ordered_keys(
        case["admission"],
        RECOVERY_EVALUATOR_ADMISSION_KEY_ORDER,
        "$.cases[0].admission",
    )
    _require_exact_value(
        _require_string(admission["relation"], "$.cases[0].admission.relation"),
        "construction_independent_ideal_acceptance",
        "$.cases[0].admission.relation",
    )
    identity_scope = _decode_variable_hex(admission["durable_identity_scope_encoding_hex"], "$.cases[0].admission.durable_identity_scope_encoding_hex")
    identity_fields = _parse_lp32_fields(identity_scope, 13, "$.cases[0].admission.durable_identity_scope_encoding_hex")
    if identity_fields[0] != STORE_IDENTITY_SCOPE_DOMAIN_V1:
        raise VerificationError("recovery evaluator identity scope has the wrong domain")
    request_id = _require_string(admission["request_id"], "$.cases[0].admission.request_id").encode("ascii")
    replay_nonce = _require_nonzero_bytes(_decode_hex(admission["replay_nonce_hex"], 32, "$.cases[0].admission.replay_nonce_hex"), 32, "$.cases[0].admission.replay_nonce_hex")
    request_expiry = _require_epoch(admission["request_expiry_unix_ms"], "$.cases[0].admission.request_expiry_unix_ms")
    checked_at = _require_epoch(admission["checked_at_unix_ms"], "$.cases[0].admission.checked_at_unix_ms")
    if checked_at > request_expiry:
        raise VerificationError("$.cases[0].admission is expired")
    request_digest = _decode_hex(admission["request_context_digest_hex"], 32, "$.cases[0].admission.request_context_digest_hex")
    authorization_digest = _decode_hex(admission["authorization_digest_hex"], 32, "$.cases[0].admission.authorization_digest_hex")
    transcript_digest = _decode_hex(admission["transcript_digest_hex"], 32, "$.cases[0].admission.transcript_digest_hex")
    provenance_digest = _decode_hex(admission["provenance_pair_digest_hex"], 32, "$.cases[0].admission.provenance_pair_digest_hex")
    statement_a = _decode_hex(admission["deriver_a_statement_digest_hex"], 32, "$.cases[0].admission.deriver_a_statement_digest_hex")
    statement_b = _decode_hex(admission["deriver_b_statement_digest_hex"], 32, "$.cases[0].admission.deriver_b_statement_digest_hex")
    replacement_credential = _require_nonzero_bytes(_decode_hex(admission["replacement_credential_binding_digest_hex"], 32, "$.cases[0].admission.replacement_credential_binding_digest_hex"), 32, "$.cases[0].admission.replacement_credential_binding_digest_hex")
    if replacement_credential == active_credential:
        raise VerificationError("recovery replacement credential did not change")
    same_root_artifact = _require_nonzero_bytes(_decode_hex(admission["provenance_same_root_artifact_digest_hex"], 32, "$.cases[0].admission.provenance_same_root_artifact_digest_hex"), 32, "$.cases[0].admission.provenance_same_root_artifact_digest_hex")
    selected_evidence = _require_nonzero_bytes(_decode_hex(admission["selected_mechanism_acceptance_evidence_digest_hex"], 32, "$.cases[0].admission.selected_mechanism_acceptance_evidence_digest_hex"), 32, "$.cases[0].admission.selected_mechanism_acceptance_evidence_digest_hex")
    next_epoch = _require_epoch(admission["next_activation_epoch"], "$.cases[0].admission.next_activation_epoch")
    if _require_epoch(admission["current_activation_epoch"], "$.cases[0].admission.current_activation_epoch") != current_epoch or next_epoch <= current_epoch:
        raise VerificationError("recovery activation epoch did not strictly advance")
    execution = _require_nonzero_bytes(_decode_hex(admission["one_use_execution_id_hex"], 32, "$.cases[0].admission.one_use_execution_id_hex"), 32, "$.cases[0].admission.one_use_execution_id_hex")
    for name, expected in (
        ("active_credential_binding_digest_hex", active_credential),
        ("registered_public_key_hex", registered_public_key),
    ):
        _require_expected_bytes(admission[name], expected, f"$.cases[0].admission.{name}")
    if _decode_variable_hex(admission["stable_scope_encoding_hex"], "$.cases[0].admission.stable_scope_encoding_hex") != stable_scope:
        raise VerificationError("admission stable scope differs from store")
    _require_exact_value(_require_string(admission["admission_state"], "$.cases[0].admission.admission_state"), "accepted_terminal_credential_suspended", "$.cases[0].admission.admission_state")

    registered_state_encoding = _lp32_join(
        (registered_public_key, active_credential, stable_scope, current_epoch.to_bytes(8, "big"), *role_fields)
    )
    store_fields = (
        AUTHENTICATED_STORE_RESOLUTION_ENCODING_DOMAIN_V1,
        authority_epoch.to_bytes(8, "big"),
        authority_digest,
        b"\x03",
        request_digest,
        authorization_digest,
        transcript_digest,
        provenance_digest,
        active_state_version.to_bytes(8, "big"),
        identity_scope,
        registered_state_encoding,
    )
    store_signing_bytes = _decode_variable_hex(store["signing_bytes_hex"], "$.cases[0].authenticated_store_resolution.signing_bytes_hex")
    if _parse_lp32_fields(store_signing_bytes, len(store_fields), "$.cases[0].authenticated_store_resolution.signing_bytes_hex") != store_fields:
        raise VerificationError("authenticated store signing bytes changed")
    store_digest = hashlib.sha256(store_signing_bytes).digest()
    _require_expected_bytes(store["signing_bytes_sha256_hex"], store_digest, "$.cases[0].authenticated_store_resolution.signing_bytes_sha256_hex")
    expected_authority_digest = hashlib.sha256(
        _lp32_join((STORE_AUTHORITY_KEY_DIGEST_DOMAIN_V1, authority_verifying_key))
    ).digest()
    if authority_digest != expected_authority_digest:
        raise VerificationError("authenticated store authority key digest changed")
    _verify_strict_ed25519_signature(
        authority_verifying_key,
        store_signing_bytes,
        _decode_hex(
            store["authority_signature_hex"],
            64,
            "$.cases[0].authenticated_store_resolution.authority_signature_hex",
        ),
        "$.cases[0].authenticated_store_resolution.authority_signature_hex",
    )

    admission_fields = (
        RECOVERY_EVALUATOR_ADMISSION_ENCODING_DOMAIN_V1,
        identity_scope,
        request_id,
        replay_nonce,
        request_expiry.to_bytes(8, "big"),
        checked_at.to_bytes(8, "big"),
        request_digest,
        authorization_digest,
        transcript_digest,
        provenance_digest,
        statement_a,
        statement_b,
        store_digest,
        authority_epoch.to_bytes(8, "big"),
        authority_digest,
        active_state_version.to_bytes(8, "big"),
        active_credential,
        replacement_credential,
        registered_public_key,
        stable_scope,
        same_root_artifact,
        selected_evidence,
        current_epoch.to_bytes(8, "big"),
        next_epoch.to_bytes(8, "big"),
        execution,
        b"\x01",
    )
    admission_encoding = _decode_variable_hex(admission["encoding_hex"], "$.cases[0].admission.encoding_hex")
    if _parse_lp32_fields(admission_encoding, len(admission_fields), "$.cases[0].admission.encoding_hex") != admission_fields:
        raise VerificationError("recovery admission encoding changed")
    admission_digest = _digest_encoding(RECOVERY_EVALUATOR_ADMISSION_DIGEST_DOMAIN_V1, admission_encoding)
    _require_expected_bytes(admission["digest_hex"], admission_digest, "$.cases[0].admission.digest_hex")

    evaluation = _require_ordered_keys(case["evaluation"], RECOVERY_EVALUATOR_EVALUATION_KEY_ORDER, "$.cases[0].evaluation")
    _require_exact_value(_require_string(evaluation["evaluation_plan"], "$.cases[0].evaluation.evaluation_plan"), "one_recovery_activation_evaluation", "$.cases[0].evaluation.evaluation_plan")
    expected_counts = {
        "yao_evaluations": 1,
        "deriver_a_invocations": 1,
        "deriver_b_invocations": 1,
        "contribution_derivations": 4,
        "output_share_samples": 2,
    }
    for name, expected in expected_counts.items():
        if type(evaluation[name]) is not int or evaluation[name] != expected:
            raise VerificationError(f"$.cases[0].evaluation.{name} must equal {expected}")
    _require_expected_bytes(evaluation["registered_public_key_hex"], registered_public_key, "$.cases[0].evaluation.registered_public_key_hex")
    package_digest = _require_nonzero_bytes(_decode_hex(evaluation["package_set_digest_hex"], 32, "$.cases[0].evaluation.package_set_digest_hex"), 32, "$.cases[0].evaluation.package_set_digest_hex")
    receipt_path = "$.cases[0].evaluation.output_committed_receipt_encoding_hex"
    receipt_encoding = _decode_variable_hex(evaluation["output_committed_receipt_encoding_hex"], receipt_path)
    receipt_fields = _parse_lp32_fields(receipt_encoding, 19, receipt_path)
    if receipt_fields[0] != ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1 or receipt_fields[1:4] != (b"\x01", b"\x01", b"\x03"):
        raise VerificationError(f"{receipt_path} has invalid domains or tags")
    for index, expected in (
        (4, request_digest),
        (5, authorization_digest),
        (6, transcript_digest),
        (9, execution),
        (10, provenance_digest),
        (11, admission_digest),
        (12, next_epoch.to_bytes(8, "big")),
        (13, package_digest),
        (16, registered_public_key),
    ):
        if receipt_fields[index] != expected:
            raise VerificationError(f"{receipt_path}[{index}] changed")
    _require_activation_public_relation(receipt_fields[14], receipt_fields[15], registered_public_key, receipt_path)
    receipt_digest = _digest_encoding(ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1, receipt_encoding)
    _require_expected_bytes(evaluation["output_committed_receipt_digest_hex"], receipt_digest, "$.cases[0].evaluation.output_committed_receipt_digest_hex")
    _require_expected_bytes(evaluation["output_committed_evaluation_evidence_digest_hex"], admission_digest, "$.cases[0].evaluation.output_committed_evaluation_evidence_digest_hex")
    _require_exact_value(_require_string(evaluation["pending_state"], "$.cases[0].evaluation.pending_state"), "recovery_pending_activation", "$.cases[0].evaluation.pending_state")
    _require_exact_value(_require_string(evaluation["old_credential_state"], "$.cases[0].evaluation.old_credential_state"), "suspended", "$.cases[0].evaluation.old_credential_state")
    if evaluation["terminal_admission_retained"] is not True:
        raise VerificationError("terminal recovery admission was not retained")

    retry = _require_ordered_keys(case["retry"], RECOVERY_EVALUATOR_RETRY_KEY_ORDER, "$.cases[0].retry")
    _require_exact_value(_require_string(retry["evaluator_abort_preserves_public_state"], "$.cases[0].retry.evaluator_abort_preserves_public_state"), "credential_suspended", "$.cases[0].retry.evaluator_abort_preserves_public_state")
    for name in RECOVERY_EVALUATOR_RETRY_KEY_ORDER[1:]:
        if retry[name] is not True:
            raise VerificationError(f"$.cases[0].retry.{name} must be true")
    claims = _require_ordered_keys(case["claim_boundary"], RECOVERY_EVALUATOR_CLAIM_KEY_ORDER, "$.cases[0].claim_boundary")
    _require_exact_value(_require_string(claims["provenance_same_root_artifact_semantics"], "claims.same_root"), "opaque_artifact_committed_by_both_provenance_statements", "claims.same_root")
    _require_exact_value(_require_string(claims["selected_mechanism_acceptance_evidence_semantics"], "claims.selected"), "opaque_acceptance_slot_instantiated_by_phase_6b", "claims.selected")
    expected_exclusions = [
        "same_root_proof_validity",
        "input_opening_consistency",
        "durable_suspension",
        "global_replay_prevention",
        "durable_one_use_uniqueness",
        "atomic_promotion",
        "rollback_floor",
        "crash_recovery",
        "profile_security",
        "transport_security",
        "production_constant_time",
    ]
    if _require_list(claims["excluded_claims"], "claims.excluded_claims") != expected_exclusions:
        raise VerificationError("recovery evaluator excluded claims changed")

    forbidden = {"proof_hex", "security_profile", "seed_output_hex", "private_root_hex", "frame_bytes_hex"}
    def scan(value: Any, path: str) -> None:
        if type(value) is dict:
            for key, nested in value.items():
                if key in forbidden:
                    raise VerificationError(f"{path}.{key} is forbidden")
                scan(nested, f"{path}.{key}")
        elif type(value) is list:
            for index, nested in enumerate(value):
                scan(nested, f"{path}[{index}]")
    scan(document, "$")
    return 1


def _activation_recipient_views_path(path: tuple[str | int, ...]) -> str:
    rendered = "$"
    for component in path:
        rendered += f"[{component}]" if type(component) is int else f".{component}"
    return rendered


def _scan_activation_recipient_views_boundary(
    value: Any, path: tuple[str | int, ...] = ()
) -> None:
    forbidden_keys = {
        "client_root_hex",
        "deriver_a_root_hex",
        "deriver_b_root_hex",
        "contributions",
        "joined_seed_hex",
        "joined_y_hex",
        "joined_tau_hex",
        "signing_scalar_hex",
        "client_scalar_share_hex",
        "signing_worker_scalar_share_hex",
        "seed_hex",
        "seed_share_hex",
        "ciphertext_bytes_hex",
        "recipient_decryption_key_hex",
        "opener_state_hex",
        "ot_state_hex",
        "garbled_table_hex",
        "label_hex",
        "mask_hex",
        "frame_bytes_hex",
        "protocol_frames",
        "durable_record",
        "durable_transaction",
        "generic_payload",
        "security_profile",
    }
    if type(value) is dict:
        for key, nested in value.items():
            nested_path = path + (key,)
            if key in forbidden_keys or key.endswith(
                ("_root_hex", "_share_hex", "_decryption_key_hex", "_frame_hex")
            ):
                raise VerificationError(
                    f"{_activation_recipient_views_path(nested_path)} is forbidden"
                )
            if key == "x_server_base_hex" and not (
                len(nested_path) == 6
                and nested_path[0] == "cases"
                and type(nested_path[1]) is int
                and nested_path[2:] == (
                    "signing_worker_activated",
                    "role_extensions",
                    "signing_worker",
                    "x_server_base_hex",
                )
            ):
                raise VerificationError(
                    f"{_activation_recipient_views_path(nested_path)} is forbidden"
                )
            _scan_activation_recipient_views_boundary(nested, nested_path)
    elif type(value) is list:
        for index, nested in enumerate(value):
            _scan_activation_recipient_views_boundary(nested, path + (index,))


def _verify_activation_recipient_empty_roles(
    extensions: dict[str, Any], path: str
) -> None:
    for role in ("deriver_a", "deriver_b", "router", "observer", "diagnostics"):
        _require_ordered_keys(extensions[role], (), f"{path}.{role}")


def _verify_activation_recipient_client_extension(
    value: Any,
    expected_package: bytes,
    expected_evidence: bytes,
    expected_scalar: int,
    expected_point: bytes,
    path: str,
) -> None:
    extension = _require_ordered_keys(
        value, ACTIVATION_RECIPIENT_VIEWS_CLIENT_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(extension["extension_kind"], f"{path}.extension_kind"),
        "activation_client_scalar_release",
        f"{path}.extension_kind",
    )
    for name, expected in (
        ("package_set_digest_hex", expected_package),
        ("delivery_evidence_digest_hex", expected_evidence),
    ):
        if _decode_hex(extension[name], 32, f"{path}.{name}") != expected:
            raise VerificationError(f"{path}.{name} changed")
    scalar = _decode_scalar(extension["x_client_base_hex"], f"{path}.x_client_base_hex")
    if scalar != expected_scalar:
        raise VerificationError(f"{path}.x_client_base_hex changed")
    if _compress_point(_multiply_base(scalar)) != expected_point:
        raise VerificationError(f"{path}.x_client_base_hex does not match X_client")


def verify_activation_recipient_party_views_corpus(
    corpus: Any,
    ceremony_context_corpus: Any,
    provenance_corpus: Any,
    semantic_lifecycle_corpus: Any,
    output_party_views_corpus: Any,
    activation_delivery_corpus: Any,
) -> int:
    """Verifies both host-only activation recipient-view stages independently."""
    semantic = _verified_semantic_lifecycle_details(
        semantic_lifecycle_corpus, ceremony_context_corpus, provenance_corpus
    )
    verify_output_party_views_corpus(
        output_party_views_corpus,
        semantic_lifecycle_corpus,
        ceremony_context_corpus,
        provenance_corpus,
    )
    verify_activation_delivery_corpus(
        activation_delivery_corpus,
        semantic_lifecycle_corpus,
        ceremony_context_corpus,
        provenance_corpus,
        output_party_views_corpus,
    )
    document = _require_ordered_keys(
        corpus, ACTIVATION_RECIPIENT_VIEWS_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    _scan_activation_recipient_views_boundary(document)

    cases = document["cases"]
    origins = ("registration", "recovery", "refresh")
    case_ids = tuple(f"{origin}_activation_recipient_party_views_v1" for origin in origins)
    delivery_case_ids = tuple(f"{origin}_activation_delivery_v1" for origin in origins)
    output_indices = (0, 2, 3)
    output_case_ids = (
        "registration_output_party_views_package_prepared_v1",
        "recovery_output_party_views_package_prepared_v1",
        "refresh_output_party_views_package_prepared_v1",
    )
    if type(cases) is not list or len(cases) != 3:
        raise VerificationError("$.cases must contain exactly three recipient party-view cases")
    delivery_cases = _require_object(activation_delivery_corpus, "$activation_delivery")[
        "cases"
    ]
    output_cases = _require_object(output_party_views_corpus, "$output_party_views")[
        "cases"
    ]

    for index, origin in enumerate(origins):
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], ACTIVATION_RECIPIENT_VIEWS_CASE_KEY_ORDER, case_path
        )
        for name, expected in (
            ("case_id", case_ids[index]),
            ("origin_request_kind", origin),
            ("activation_delivery_case_id", delivery_case_ids[index]),
            ("output_party_view_case_id", output_case_ids[index]),
        ):
            _require_exact_value(
                _require_string(case[name], f"{case_path}.{name}"),
                expected,
                f"{case_path}.{name}",
            )

        delivery_case = _require_object(
            delivery_cases[index], f"$activation_delivery.cases[{index}]"
        )
        output_case = _require_object(
            output_cases[output_indices[index]],
            f"$output_party_views.cases[{output_indices[index]}]",
        )
        output_vector = _require_object(output_case["vector"], "$output_party.vector")
        _require_exact_value(
            _require_string(output_vector["case_id"], "$output_party.vector.case_id"),
            output_case_ids[index],
            "$output_party.vector.case_id",
        )
        output_extensions = _require_object(
            output_vector["role_extensions"], "$output_party.vector.role_extensions"
        )
        _require_exact_value(
            _require_string(output_extensions["client"]["kind"], "$output_party.client.kind"),
            "client_no_private_output",
            "$output_party.client.kind",
        )
        _require_exact_value(
            _require_string(
                output_extensions["signing_worker"]["kind"],
                "$output_party.signing_worker.kind",
            ),
            "signing_worker_no_private_output",
            "$output_party.signing_worker.kind",
        )

        semantic_origin = semantic["origins"][origin]
        receipt = semantic_origin["receipt"]
        packages = semantic_origin["packages"]
        activation = semantic["activation_control"]["metadata_consumed"][index][
            "activation"
        ]
        expected_package = packages["package_set_digest"]
        expected_output_receipt = receipt["receipt_digest"]
        expected_x_client = receipt["x_client"]
        expected_x_server = receipt["x_server"]
        expected_registered_key = receipt["registered_public_key"]
        expected_epoch = packages["activation_epoch"]

        delivery_released = _require_object(
            delivery_case["recipients_released"], "$activation_delivery.recipients_released"
        )
        delivery_client = _require_object(
            delivery_released["client"], "$activation_delivery.recipients_released.client"
        )
        delivery_worker = _require_object(
            delivery_released["signing_worker"],
            "$activation_delivery.recipients_released.signing_worker",
        )
        expected_client_evidence = _decode_hex(
            delivery_client["delivery_evidence_digest_hex"],
            32,
            "$activation_delivery.client.delivery_evidence_digest_hex",
        )
        expected_worker_evidence = _decode_hex(
            delivery_worker["delivery_evidence_digest_hex"],
            32,
            "$activation_delivery.signing_worker.delivery_evidence_digest_hex",
        )
        client_a = _decode_scalar(
            output_extensions["deriver_a"]["client_scalar_share_hex"],
            "$output_party.deriver_a.client_scalar_share_hex",
        )
        client_b = _decode_scalar(
            output_extensions["deriver_b"]["client_scalar_share_hex"],
            "$output_party.deriver_b.client_scalar_share_hex",
        )
        worker_a = _decode_scalar(
            output_extensions["deriver_a"]["signing_worker_scalar_share_hex"],
            "$output_party.deriver_a.signing_worker_scalar_share_hex",
        )
        worker_b = _decode_scalar(
            output_extensions["deriver_b"]["signing_worker_scalar_share_hex"],
            "$output_party.deriver_b.signing_worker_scalar_share_hex",
        )
        expected_client_scalar = (client_a + client_b) % SCALAR_ORDER
        expected_worker_scalar = (worker_a + worker_b) % SCALAR_ORDER

        released_path = f"{case_path}.recipients_released"
        released = _require_ordered_keys(
            case["recipients_released"],
            ACTIVATION_RECIPIENT_VIEWS_STAGE_KEY_ORDER,
            released_path,
        )
        released_common_path = f"{released_path}.common_public"
        released_common = _require_ordered_keys(
            released["common_public"],
            ACTIVATION_RECIPIENT_VIEWS_RELEASE_COMMON_KEY_ORDER,
            released_common_path,
        )
        for name, expected in (
            ("stage", "recipients_released"),
            ("origin_request_kind", origin),
            ("activation_authorization_state", "consumed"),
        ):
            _require_exact_value(
                _require_string(released_common[name], f"{released_common_path}.{name}"),
                expected,
                f"{released_common_path}.{name}",
            )
        for name, expected in (
            ("package_set_digest_hex", expected_package),
            ("output_committed_receipt_digest_hex", expected_output_receipt),
            ("activation_transcript_digest_hex", activation["transcript_digest"]),
        ):
            if _decode_hex(released_common[name], 32, f"{released_common_path}.{name}") != expected:
                raise VerificationError(f"{released_common_path}.{name} changed")
        _verify_activation_delivery_zero_work(
            released_common["zero_private_evaluation_work"],
            f"{released_common_path}.zero_private_evaluation_work",
        )
        released_extensions_path = f"{released_path}.role_extensions"
        released_extensions = _require_ordered_keys(
            released["role_extensions"],
            ACTIVATION_RECIPIENT_VIEWS_ROLE_EXTENSIONS_KEY_ORDER,
            released_extensions_path,
        )
        _verify_activation_recipient_empty_roles(released_extensions, released_extensions_path)
        _verify_activation_recipient_client_extension(
            released_extensions["client"],
            expected_package,
            expected_client_evidence,
            expected_client_scalar,
            expected_x_client,
            f"{released_extensions_path}.client",
        )
        released_worker_path = f"{released_extensions_path}.signing_worker"
        released_worker = _require_ordered_keys(
            released_extensions["signing_worker"],
            ACTIVATION_RECIPIENT_VIEWS_RELEASE_WORKER_KEY_ORDER,
            released_worker_path,
        )
        _require_exact_value(
            _require_string(
                released_worker["extension_kind"], f"{released_worker_path}.extension_kind"
            ),
            "signing_worker_activation_release_authority",
            f"{released_worker_path}.extension_kind",
        )
        for name, expected in (
            ("package_set_digest_hex", expected_package),
            ("delivery_evidence_digest_hex", expected_worker_evidence),
        ):
            if _decode_hex(released_worker[name], 32, f"{released_worker_path}.{name}") != expected:
                raise VerificationError(f"{released_worker_path}.{name} changed")

        activated_path = f"{case_path}.signing_worker_activated"
        activated = _require_ordered_keys(
            case["signing_worker_activated"],
            ACTIVATION_RECIPIENT_VIEWS_STAGE_KEY_ORDER,
            activated_path,
        )
        activated_common_path = f"{activated_path}.common_public"
        activated_common = _require_ordered_keys(
            activated["common_public"],
            ACTIVATION_RECIPIENT_VIEWS_ACTIVATED_COMMON_KEY_ORDER,
            activated_common_path,
        )
        for name, expected in (
            ("stage", "signing_worker_activated"),
            ("origin_request_kind", origin),
            ("activation_authorization_state", "consumed"),
        ):
            _require_exact_value(
                _require_string(activated_common[name], f"{activated_common_path}.{name}"),
                expected,
                f"{activated_common_path}.{name}",
            )
        for name, expected in (
            ("package_set_digest_hex", expected_package),
            ("output_committed_receipt_digest_hex", expected_output_receipt),
            ("registered_public_key_hex", expected_registered_key),
            ("x_server_hex", expected_x_server),
        ):
            if _decode_hex(activated_common[name], 32, f"{activated_common_path}.{name}") != expected:
                raise VerificationError(f"{activated_common_path}.{name} changed")
        if _require_epoch(
            activated_common["activation_epoch"], f"{activated_common_path}.activation_epoch"
        ) != expected_epoch:
            raise VerificationError(f"{activated_common_path}.activation_epoch changed")

        origin_request_fields = semantic_origin["ceremony"]["request_fields"]
        expected_worker_id = origin_request_fields[b"signingWorkerId"]
        expected_worker_key_epoch = int.from_bytes(
            origin_request_fields[b"signingWorkerKeyEpoch"], "big"
        )
        worker_id = _require_string(
            activated_common["signing_worker_id"],
            f"{activated_common_path}.signing_worker_id",
        )
        try:
            worker_id_bytes = worker_id.encode("ascii")
        except UnicodeEncodeError as error:
            raise VerificationError(
                f"{activated_common_path}.signing_worker_id must be visible ASCII"
            ) from error
        _require_visible_ascii_bytes(
            worker_id_bytes,
            f"{activated_common_path}.signing_worker_id",
        )
        if worker_id_bytes != expected_worker_id:
            raise VerificationError(f"{activated_common_path}.signing_worker_id changed")
        worker_key_epoch = _require_epoch(
            activated_common["signing_worker_recipient_key_epoch"],
            f"{activated_common_path}.signing_worker_recipient_key_epoch",
        )
        if worker_key_epoch != expected_worker_key_epoch:
            raise VerificationError(
                f"{activated_common_path}.signing_worker_recipient_key_epoch changed"
            )
        storage_evidence = _require_nonzero_bytes(
            _decode_hex(
                activated_common["output_storage_evidence_digest_hex"],
                32,
                f"{activated_common_path}.output_storage_evidence_digest_hex",
            ),
            32,
            f"{activated_common_path}.output_storage_evidence_digest_hex",
        )
        receipt_key_epoch = _require_epoch(
            activated_common["receipt_key_epoch"],
            f"{activated_common_path}.receipt_key_epoch",
        )
        receipt_verifying_key = _decode_hex(
            activated_common["receipt_verifying_key_hex"],
            32,
            f"{activated_common_path}.receipt_verifying_key_hex",
        )
        trusted_receipt_key_epoch, trusted_receipt_verifying_key = (
            ACTIVATION_RECIPIENT_TRUSTED_RECEIPT_AUTHORITIES_V1[origin]
        )
        if receipt_key_epoch != trusted_receipt_key_epoch:
            raise VerificationError(
                f"{activated_common_path}.receipt_key_epoch is not the pinned fixture authority epoch"
            )
        if receipt_verifying_key != trusted_receipt_verifying_key:
            raise VerificationError(
                f"{activated_common_path}.receipt_verifying_key_hex is not the pinned fixture authority"
            )
        receipt_key_digest = hashlib.sha256(
            _lp32_join(
                (
                    SIGNING_WORKER_RECEIPT_KEY_DIGEST_DOMAIN_V1,
                    expected_worker_id,
                    worker_key_epoch.to_bytes(8, "big"),
                    receipt_verifying_key,
                )
            )
        ).digest()
        if _decode_hex(
            activated_common["receipt_key_digest_hex"],
            32,
            f"{activated_common_path}.receipt_key_digest_hex",
        ) != receipt_key_digest:
            raise VerificationError(f"{activated_common_path}.receipt_key_digest_hex changed")

        origin_tag = index + 1
        expected_receipt_encoding = _lp32_join(
            (
                SIGNING_WORKER_ACTIVATION_RECEIPT_ENCODING_DOMAIN_V1,
                receipt_key_epoch.to_bytes(8, "big"),
                receipt_key_digest,
                expected_worker_id,
                worker_key_epoch.to_bytes(8, "big"),
                bytes((origin_tag,)),
                activation["request_digest"],
                activation["authorization_digest"],
                activation["transcript_digest"],
                bytes((origin_tag,)),
                bytes((CEREMONY_KIND_METADATA_V1[origin][0],)),
                semantic_origin["ceremony"]["request_digest"],
                semantic_origin["ceremony"]["authorization_digest"],
                semantic_origin["ceremony"]["transcript_digest"],
                packages["binding"]["one_use_execution_id"],
                expected_package,
                expected_epoch.to_bytes(8, "big"),
                expected_registered_key,
                expected_output_receipt,
                expected_x_server,
                expected_registered_key,
                storage_evidence,
            )
        )
        if _decode_variable_hex(
            activated_common["activation_receipt_encoding_hex"],
            f"{activated_common_path}.activation_receipt_encoding_hex",
        ) != expected_receipt_encoding:
            raise VerificationError(
                f"{activated_common_path}.activation_receipt_encoding_hex changed"
            )
        expected_receipt_digest = hashlib.sha256(
            _lp32_join(
                (
                    SIGNING_WORKER_ACTIVATION_RECEIPT_DIGEST_DOMAIN_V1,
                    expected_receipt_encoding,
                )
            )
        ).digest()
        if _decode_hex(
            activated_common["activation_receipt_digest_hex"],
            32,
            f"{activated_common_path}.activation_receipt_digest_hex",
        ) != expected_receipt_digest:
            raise VerificationError(f"{activated_common_path}.activation_receipt_digest_hex changed")
        receipt_signature = _decode_hex(
            activated_common["activation_receipt_signature_hex"],
            64,
            f"{activated_common_path}.activation_receipt_signature_hex",
        )
        _verify_strict_ed25519_signature(
            receipt_verifying_key,
            expected_receipt_encoding,
            receipt_signature,
            f"{activated_common_path}.activation_receipt_signature_hex",
        )

        activated_extensions_path = f"{activated_path}.role_extensions"
        activated_extensions = _require_ordered_keys(
            activated["role_extensions"],
            ACTIVATION_RECIPIENT_VIEWS_ROLE_EXTENSIONS_KEY_ORDER,
            activated_extensions_path,
        )
        _verify_activation_recipient_empty_roles(activated_extensions, activated_extensions_path)
        _verify_activation_recipient_client_extension(
            activated_extensions["client"],
            expected_package,
            expected_client_evidence,
            expected_client_scalar,
            expected_x_client,
            f"{activated_extensions_path}.client",
        )
        if activated_extensions["client"] != released_extensions["client"]:
            raise VerificationError(f"{activated_extensions_path}.client changed after release")
        activated_worker_path = f"{activated_extensions_path}.signing_worker"
        activated_worker = _require_ordered_keys(
            activated_extensions["signing_worker"],
            ACTIVATION_RECIPIENT_VIEWS_ACTIVATED_WORKER_KEY_ORDER,
            activated_worker_path,
        )
        _require_exact_value(
            _require_string(
                activated_worker["extension_kind"],
                f"{activated_worker_path}.extension_kind",
            ),
            "sealed_signing_worker_activated_state",
            f"{activated_worker_path}.extension_kind",
        )
        worker_scalar = _decode_scalar(
            activated_worker["x_server_base_hex"],
            f"{activated_worker_path}.x_server_base_hex",
        )
        if worker_scalar != expected_worker_scalar:
            raise VerificationError(f"{activated_worker_path}.x_server_base_hex changed")
        if _compress_point(_multiply_base(worker_scalar)) != expected_x_server:
            raise VerificationError(f"{activated_worker_path}.x_server_base_hex does not match X_server")
        _require_activation_public_relation(
            expected_x_client,
            expected_x_server,
            expected_registered_key,
            f"{activated_common_path}.registered_key_relation",
        )
    return len(cases)


def _verify_recovery_transition_state(value: Any, path: str) -> dict[str, Any]:
    state = _require_ordered_keys(value, RECOVERY_TRANSITION_STATE_KEY_ORDER, path)
    decoded: dict[str, Any] = {
        "active_state_version": _require_epoch(
            state["active_state_version"], f"{path}.active_state_version"
        ),
        "active_activation_epoch": _require_epoch(
            state["active_activation_epoch"], f"{path}.active_activation_epoch"
        ),
        "deriver_a_root_epoch": _require_epoch(
            state["deriver_a_root_epoch"], f"{path}.deriver_a_root_epoch"
        ),
        "deriver_a_input_state_epoch": _require_epoch(
            state["deriver_a_input_state_epoch"],
            f"{path}.deriver_a_input_state_epoch",
        ),
        "deriver_b_root_epoch": _require_epoch(
            state["deriver_b_root_epoch"], f"{path}.deriver_b_root_epoch"
        ),
        "deriver_b_input_state_epoch": _require_epoch(
            state["deriver_b_input_state_epoch"],
            f"{path}.deriver_b_input_state_epoch",
        ),
    }
    for name in (
        "registered_public_key_hex",
        "active_credential_binding_digest_hex",
        "deriver_a_root_record_hex",
        "deriver_a_root_binding_hex",
        "deriver_a_state_record_hex",
        "deriver_b_root_record_hex",
        "deriver_b_root_binding_hex",
        "deriver_b_state_record_hex",
    ):
        decoded[name] = _decode_hex(state[name], 32, f"{path}.{name}")
    decoded["stable_scope_encoding_hex"] = _decode_variable_hex(
        state["stable_scope_encoding_hex"], f"{path}.stable_scope_encoding_hex"
    )
    return decoded


def _recovery_transition_state_digest(state: dict[str, Any]) -> bytes:
    return hashlib.sha256(
        _lp32_join(
            (
                RECOVERY_PROMOTION_STATE_DIGEST_DOMAIN_V1,
                state["registered_public_key_hex"],
                state["active_credential_binding_digest_hex"],
                state["stable_scope_encoding_hex"],
                state["active_activation_epoch"].to_bytes(8, "big"),
                state["deriver_a_root_record_hex"],
                state["deriver_a_root_binding_hex"],
                state["deriver_a_root_epoch"].to_bytes(8, "big"),
                state["deriver_a_state_record_hex"],
                state["deriver_a_input_state_epoch"].to_bytes(8, "big"),
                state["deriver_b_root_record_hex"],
                state["deriver_b_root_binding_hex"],
                state["deriver_b_root_epoch"].to_bytes(8, "big"),
                state["deriver_b_state_record_hex"],
                state["deriver_b_input_state_epoch"].to_bytes(8, "big"),
            )
        )
    ).digest()


def _scan_recovery_transition_boundary(
    value: Any, path: tuple[str | int, ...] = ()
) -> None:
    forbidden = {
        "security_profile",
        "client_root_hex",
        "deriver_a_root_hex",
        "deriver_b_root_hex",
        "joined_seed_hex",
        "signing_scalar_hex",
        "x_server_base_hex",
        "transport_frame",
        "durable_transaction_succeeded",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            if key in forbidden:
                raise VerificationError(
                    f"{_activation_recipient_views_path(path + (key,))} is forbidden"
                )
            _scan_recovery_transition_boundary(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_recovery_transition_boundary(child, path + (index,))


def verify_recovery_credential_transition_corpus(
    corpus: Any,
    ceremony_context_corpus: Any,
    provenance_corpus: Any,
    semantic_lifecycle_corpus: Any,
    output_party_views_corpus: Any,
    activation_delivery_corpus: Any,
    activation_recipient_party_views_corpus: Any,
) -> int:
    document = _require_ordered_keys(corpus, RECOVERY_TRANSITION_CORPUS_KEY_ORDER, "$")
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        RECOVERY_CREDENTIAL_TRANSITION_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    verify_activation_recipient_party_views_corpus(
        activation_recipient_party_views_corpus,
        ceremony_context_corpus,
        provenance_corpus,
        semantic_lifecycle_corpus,
        output_party_views_corpus,
        activation_delivery_corpus,
    )
    cases = _require_list(document["cases"], "$.cases")
    if len(cases) != 1:
        raise VerificationError("$.cases must contain exactly one recovery transition")
    case = _require_ordered_keys(cases[0], RECOVERY_TRANSITION_CASE_KEY_ORDER, "$.cases[0]")
    _require_exact_value(_require_string(case["case_id"], "$.cases[0].case_id"), "recovery_credential_suspension_promotion_v1", "$.cases[0].case_id")
    _require_exact_value(_require_string(case["request_kind"], "$.cases[0].request_kind"), "recovery", "$.cases[0].request_kind")
    sources = _require_ordered_keys(case["source_references"], RECOVERY_TRANSITION_SOURCE_KEY_ORDER, "$.cases[0].source_references")
    source_values = (
        ("ceremony_context_case_id", "ceremony-recovery-v1"),
        ("provenance_case_id", "recovery_provenance_outer_v1"),
        ("semantic_lifecycle_case_id", "recovery_semantic_artifacts_output_committed_v1"),
        ("activation_delivery_case_id", "recovery_activation_delivery_v1"),
        ("activation_recipient_party_view_case_id", "recovery_activation_recipient_party_views_v1"),
    )
    for name, expected in source_values:
        _require_exact_value(_require_string(sources[name], f"$.cases[0].source_references.{name}"), expected, f"$.cases[0].source_references.{name}")

    suspended = _require_ordered_keys(case["suspended"], RECOVERY_TRANSITION_SUSPENDED_KEY_ORDER, "$.cases[0].suspended")
    _require_exact_value(_require_string(suspended["credential_state"], "$.cases[0].suspended.credential_state"), "suspended", "$.cases[0].suspended.credential_state")
    old_version = _require_epoch(suspended["old_active_state_version"], "$.cases[0].suspended.old_active_state_version")
    old_credential = _require_nonzero_bytes(_decode_hex(suspended["old_credential_binding_digest_hex"], 32, "$.cases[0].suspended.old_credential_binding_digest_hex"), 32, "$.cases[0].suspended.old_credential_binding_digest_hex")
    replacement_credential = _require_nonzero_bytes(_decode_hex(suspended["replacement_credential_binding_digest_hex"], 32, "$.cases[0].suspended.replacement_credential_binding_digest_hex"), 32, "$.cases[0].suspended.replacement_credential_binding_digest_hex")
    if replacement_credential == old_credential:
        raise VerificationError("$.cases[0].suspended replacement credential must be distinct")
    same_root = _require_nonzero_bytes(_decode_hex(suspended["same_root_evidence_artifact_digest_hex"], 32, "$.cases[0].suspended.same_root_evidence_artifact_digest_hex"), 32, "$.cases[0].suspended.same_root_evidence_artifact_digest_hex")

    provenance_cases = _require_list(_require_object(provenance_corpus, "provenance")["cases"], "provenance.cases")
    recovery_provenance = next((entry for entry in provenance_cases if _require_object(entry, "provenance.case").get("request_kind") == "recovery"), None)
    if recovery_provenance is None:
        raise VerificationError("provenance companion lacks recovery")
    recovery_vector = _require_object(_require_object(recovery_provenance, "provenance.recovery")["vector"], "provenance.recovery.vector")
    for role in ("deriver_a", "deriver_b"):
        branch = _decode_variable_hex(_require_object(recovery_vector[role], f"provenance.{role}")["branch_encoding_hex"], f"provenance.{role}.branch_encoding_hex")
        if _parse_lp32_fields(branch, 4, f"provenance.{role}.branch_encoding_hex")[-1] != same_root:
            raise VerificationError(f"provenance.{role} same-root evidence changed")

    activated = _require_ordered_keys(case["worker_activated"], RECOVERY_TRANSITION_WORKER_ACTIVATED_KEY_ORDER, "$.cases[0].worker_activated")
    recipient_cases = _require_list(_require_object(activation_recipient_party_views_corpus, "activation-recipient")["cases"], "activation-recipient.cases")
    recipient_case = next((entry for entry in recipient_cases if _require_object(entry, "activation-recipient.case").get("origin_request_kind") == "recovery"), None)
    if recipient_case is None:
        raise VerificationError("activation-recipient companion lacks recovery")
    recipient_common = _require_object(_require_object(_require_object(recipient_case, "activation-recipient.recovery")["signing_worker_activated"], "activation-recipient.activated")["common_public"], "activation-recipient.common")
    activated_bytes = {
        "activation_receipt_digest_hex": _decode_hex(activated["activation_receipt_digest_hex"], 32, "$.cases[0].worker_activated.activation_receipt_digest_hex"),
        "package_set_digest_hex": _decode_hex(activated["package_set_digest_hex"], 32, "$.cases[0].worker_activated.package_set_digest_hex"),
        "output_committed_receipt_digest_hex": _decode_hex(activated["output_committed_receipt_digest_hex"], 32, "$.cases[0].worker_activated.output_committed_receipt_digest_hex"),
        "worker_storage_receipt_digest_hex": _decode_hex(activated["worker_storage_receipt_digest_hex"], 32, "$.cases[0].worker_activated.worker_storage_receipt_digest_hex"),
    }
    recipient_names = {
        "activation_receipt_digest_hex": "activation_receipt_digest_hex",
        "package_set_digest_hex": "package_set_digest_hex",
        "output_committed_receipt_digest_hex": "output_committed_receipt_digest_hex",
        "worker_storage_receipt_digest_hex": "output_storage_evidence_digest_hex",
    }
    for name, recipient_name in recipient_names.items():
        if activated_bytes[name] != _decode_hex(recipient_common[recipient_name], 32, f"activation-recipient.common.{recipient_name}"):
            raise VerificationError(f"$.cases[0].worker_activated.{name} changed")
    activation_epoch = _require_epoch(activated["activation_epoch"], "$.cases[0].worker_activated.activation_epoch")
    if activation_epoch != _require_epoch(recipient_common["activation_epoch"], "activation-recipient.common.activation_epoch"):
        raise VerificationError("$.cases[0].worker_activated.activation_epoch changed")

    promoted = _require_ordered_keys(case["promoted"], RECOVERY_TRANSITION_PROMOTED_KEY_ORDER, "$.cases[0].promoted")
    _require_exact_value(_require_string(promoted["credential_state"], "$.cases[0].promoted.credential_state"), "active", "$.cases[0].promoted.credential_state")
    old_state = _verify_recovery_transition_state(promoted["old_state"], "$.cases[0].promoted.old_state")
    next_state = _verify_recovery_transition_state(promoted["next_state"], "$.cases[0].promoted.next_state")
    if old_state["active_state_version"] != old_version or old_state["active_credential_binding_digest_hex"] != old_credential:
        raise VerificationError("$.cases[0].promoted.old_state differs from suspension")
    if next_state["active_state_version"] <= old_version or next_state["active_activation_epoch"] != activation_epoch or next_state["active_credential_binding_digest_hex"] != replacement_credential:
        raise VerificationError("$.cases[0].promoted.next_state is not the authorized monotonic promotion")
    for name in RECOVERY_TRANSITION_STATE_KEY_ORDER:
        if name not in {"active_state_version", "active_credential_binding_digest_hex", "active_activation_epoch"} and old_state[name] != next_state[name]:
            raise VerificationError(f"$.cases[0].promoted.next_state.{name} changed")
    if next_state["registered_public_key_hex"] != _decode_hex(recipient_common["registered_public_key_hex"], 32, "activation-recipient.common.registered_public_key_hex"):
        raise VerificationError("$.cases[0].promoted registered key changed")

    tombstone = _require_ordered_keys(promoted["tombstone"], RECOVERY_TRANSITION_TOMBSTONE_KEY_ORDER, "$.cases[0].promoted.tombstone")
    _require_exact_value(_require_string(tombstone["credential_state"], "$.cases[0].promoted.tombstone.credential_state"), "tombstoned", "$.cases[0].promoted.tombstone.credential_state")
    if _decode_hex(tombstone["credential_binding_digest_hex"], 32, "$.cases[0].promoted.tombstone.credential_binding_digest_hex") != old_credential or _require_epoch(tombstone["retired_state_version"], "$.cases[0].promoted.tombstone.retired_state_version") != old_version:
        raise VerificationError("$.cases[0].promoted.tombstone changed")
    expected_tombstone_digest = hashlib.sha256(_lp32_join((RECOVERY_CREDENTIAL_TOMBSTONE_DIGEST_DOMAIN_V1, old_credential, old_version.to_bytes(8, "big")))).digest()
    if _decode_hex(tombstone["tombstone_digest_hex"], 32, "$.cases[0].promoted.tombstone.tombstone_digest_hex") != expected_tombstone_digest:
        raise VerificationError("$.cases[0].promoted.tombstone.tombstone_digest_hex changed")

    transaction_digest = _require_nonzero_bytes(_decode_hex(promoted["transaction_receipt_digest_hex"], 32, "$.cases[0].promoted.transaction_receipt_digest_hex"), 32, "$.cases[0].promoted.transaction_receipt_digest_hex")
    receipt_encoding = _decode_variable_hex(promoted["promotion_receipt_encoding_hex"], "$.cases[0].promoted.promotion_receipt_encoding_hex")
    receipt_fields = _parse_lp32_fields(receipt_encoding, 20, "$.cases[0].promoted.promotion_receipt_encoding_hex")
    pinned_key = _derive_ed25519_public_key_from_seed(bytes((0x5A,)) * 32)
    authority_digest = hashlib.sha256(_lp32_join((STORE_AUTHORITY_KEY_DIGEST_DOMAIN_V1, pinned_key))).digest()
    durable_identity = _lp32_join((STORE_IDENTITY_SCOPE_DOMAIN_V1, b"walletId", b"wallet-fixture", b"organizationId", b"organization-fixture", b"projectId", b"project-fixture", b"environmentId", b"environment-fixture", b"signingRootId", b"project-fixture:environment-fixture", b"chainTarget", b"near:testnet"))
    expected_fields = (
        RECOVERY_PROMOTION_ENCODING_DOMAIN_V1,
        (1).to_bytes(8, "big"),
        authority_digest,
        durable_identity,
        old_version.to_bytes(8, "big"),
        next_state["active_state_version"].to_bytes(8, "big"),
        activated_bytes["activation_receipt_digest_hex"],
        _require_string(recipient_common["signing_worker_id"], "activation-recipient.common.signing_worker_id").encode("ascii"),
        _require_epoch(recipient_common["signing_worker_recipient_key_epoch"], "activation-recipient.common.signing_worker_recipient_key_epoch").to_bytes(8, "big"),
        activation_epoch.to_bytes(8, "big"),
        activated_bytes["package_set_digest_hex"],
        activated_bytes["output_committed_receipt_digest_hex"],
        activated_bytes["worker_storage_receipt_digest_hex"],
        _recovery_transition_state_digest(old_state),
        _recovery_transition_state_digest(next_state),
        old_credential,
        replacement_credential,
        same_root,
        expected_tombstone_digest,
        transaction_digest,
    )
    if receipt_fields != expected_fields:
        raise VerificationError("$.cases[0].promoted.promotion_receipt_encoding_hex changed")
    expected_receipt_digest = hashlib.sha256(_lp32_join((RECOVERY_PROMOTION_RECEIPT_DIGEST_DOMAIN_V1, receipt_encoding))).digest()
    if _decode_hex(promoted["promotion_receipt_digest_hex"], 32, "$.cases[0].promoted.promotion_receipt_digest_hex") != expected_receipt_digest:
        raise VerificationError("$.cases[0].promoted.promotion_receipt_digest_hex changed")
    _verify_strict_ed25519_signature(pinned_key, receipt_encoding, _decode_hex(promoted["promotion_receipt_signature_hex"], 64, "$.cases[0].promoted.promotion_receipt_signature_hex"), "$.cases[0].promoted.promotion_receipt_signature_hex")
    _scan_recovery_transition_boundary(document)
    return 1


def _evaluation_input_base_contributions(
    context_binding: bytes,
) -> dict[str, dict[str, bytes]]:
    client_a_y, client_a_tau = _derive_kdf_contribution(
        LIFECYCLE_CLIENT_ROOT_V1, context_binding, 0x01, 0x01
    )
    client_b_y, client_b_tau = _derive_kdf_contribution(
        LIFECYCLE_CLIENT_ROOT_V1, context_binding, 0x02, 0x01
    )
    server_a_y, server_a_tau = _derive_kdf_contribution(
        LIFECYCLE_DERIVER_A_ROOT_V1, context_binding, 0x01, 0x02
    )
    server_b_y, server_b_tau = _derive_kdf_contribution(
        LIFECYCLE_DERIVER_B_ROOT_V1, context_binding, 0x02, 0x02
    )
    return {
        "deriver_a": {
            "y_client": client_a_y,
            "y_server": server_a_y,
            "tau_client": client_a_tau,
            "tau_server": server_a_tau,
        },
        "deriver_b": {
            "y_client": client_b_y,
            "y_server": server_b_y,
            "tau_client": client_b_tau,
            "tau_server": server_b_tau,
        },
    }


def _evaluation_input_refreshed_contributions(
    base: dict[str, dict[str, bytes]],
) -> dict[str, dict[str, bytes]]:
    refreshed = {
        role: dict(contribution) for role, contribution in base.items()
    }
    refreshed["deriver_a"]["y_server"] = _wrapping_add_256(
        base["deriver_a"]["y_server"], LIFECYCLE_DELTA_Y_V1
    )
    refreshed["deriver_b"]["y_server"] = _wrapping_sub_256(
        base["deriver_b"]["y_server"], LIFECYCLE_DELTA_Y_V1
    )
    refreshed["deriver_a"]["tau_server"] = _encode_scalar(
        int.from_bytes(base["deriver_a"]["tau_server"], "little")
        + LIFECYCLE_DELTA_TAU_V1
    )
    refreshed["deriver_b"]["tau_server"] = _encode_scalar(
        int.from_bytes(base["deriver_b"]["tau_server"], "little")
        - LIFECYCLE_DELTA_TAU_V1
    )
    return refreshed


def _evaluation_input_provenance_records(
    provenance_corpus: Any,
) -> dict[str, dict[str, Any]]:
    cases = _require_object(provenance_corpus, "$")["cases"]
    records: dict[str, dict[str, Any]] = {}
    for index, (request_kind, case_id, _) in enumerate(
        PROVENANCE_CASE_SEQUENCE_V1
    ):
        vector = cases[index]["vector"]
        a_scope = _verify_provenance_stable_scope(
            _decode_variable_hex(
                vector["deriver_a"]["stable_scope_encoding_hex"],
                f"$provenance.cases[{index}].vector.deriver_a.stable_scope_encoding_hex",
            ),
            f"$provenance.cases[{index}].vector.deriver_a.stable_scope",
        )
        b_scope = _verify_provenance_stable_scope(
            _decode_variable_hex(
                vector["deriver_b"]["stable_scope_encoding_hex"],
                f"$provenance.cases[{index}].vector.deriver_b.stable_scope_encoding_hex",
            ),
            f"$provenance.cases[{index}].vector.deriver_b.stable_scope",
        )
        if a_scope != b_scope:
            raise VerificationError(
                f"$provenance.cases[{index}] A/B stable scopes differ"
            )
        records[request_kind] = {
            "case_id": case_id,
            "context_binding": a_scope[3],
            "request_digest": _decode_hex(
                vector["public_request_context_digest_hex"],
                32,
                f"$provenance.cases[{index}].vector.public_request_context_digest_hex",
            ),
            "authorization_digest": _decode_hex(
                vector["authorization_digest_hex"],
                32,
                f"$provenance.cases[{index}].vector.authorization_digest_hex",
            ),
            "transcript_digest": _decode_hex(
                vector["transcript_digest_hex"],
                32,
                f"$provenance.cases[{index}].vector.transcript_digest_hex",
            ),
            "pair_digest": _decode_hex(
                vector["pair_digest_sha256_hex"],
                32,
                f"$provenance.cases[{index}].vector.pair_digest_sha256_hex",
            ),
        }
    registration_binding = records["registration"]["context_binding"]
    for request_kind, record in records.items():
        if record["context_binding"] != registration_binding:
            raise VerificationError(
                f"$provenance {request_kind} changed the frozen stable KDF context"
            )
    return records


def _verify_evaluation_input_plan(
    value: Any,
    expected_kind: str,
    expected_counts: tuple[int, int, int, int, int],
    path: str,
) -> dict[str, Any]:
    plan = _require_ordered_keys(
        value, EVALUATION_INPUT_PARTY_VIEWS_EVALUATION_PLAN_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(plan["kind"], f"{path}.kind"),
        expected_kind,
        f"{path}.kind",
    )
    counts_path = f"{path}.counts"
    counts = _require_ordered_keys(
        plan["counts"],
        EVALUATION_INPUT_PARTY_VIEWS_EVALUATION_COUNTS_KEY_ORDER,
        counts_path,
    )
    for field_name, expected in zip(
        EVALUATION_INPUT_PARTY_VIEWS_EVALUATION_COUNTS_KEY_ORDER,
        expected_counts,
    ):
        actual = _require_u8(counts[field_name], f"{counts_path}.{field_name}")
        if actual != expected:
            raise VerificationError(
                f"{counts_path}.{field_name} must equal {expected} for {expected_kind}"
            )
    return plan


def _verify_evaluation_input_source_references(
    value: Any,
    request_kind: str,
    ceremony_case_id: str | None,
    provenance_case_id: str | None,
    semantic_case_id: str,
    output_party_case_id: str,
    path: str,
) -> None:
    if request_kind == "activation":
        references = _require_ordered_keys(
            value,
            EVALUATION_INPUT_PARTY_VIEWS_ACTIVATION_SOURCE_REFERENCES_KEY_ORDER,
            path,
        )
        expected = {
            "semantic_lifecycle_case_id": semantic_case_id,
            "output_party_view_case_id": output_party_case_id,
            "activation_origin": "registration",
        }
    else:
        references = _require_ordered_keys(
            value, EVALUATION_INPUT_PARTY_VIEWS_SOURCE_REFERENCES_KEY_ORDER, path
        )
        if ceremony_case_id is None or provenance_case_id is None:
            raise VerificationError(f"{path} lacks a producing-branch companion")
        expected = {
            "ceremony_context_case_id": ceremony_case_id,
            "provenance_case_id": provenance_case_id,
            "semantic_lifecycle_case_id": semantic_case_id,
            "output_party_view_case_id": output_party_case_id,
        }
    if references != expected:
        raise VerificationError(f"{path} differs from its independently verified companions")


def _verify_evaluation_input_common(
    value: Any,
    request_kind: str,
    stage: str,
    request_digest: bytes,
    authorization_digest: bytes,
    transcript_digest: bytes,
    provenance_pair_digest: bytes | None,
    path: str,
) -> None:
    if request_kind == "activation":
        common = _require_ordered_keys(
            value, EVALUATION_INPUT_PARTY_VIEWS_ACTIVATION_COMMON_KEY_ORDER, path
        )
        plan = _verify_evaluation_input_plan(
            common["evaluation_plan"],
            "zero_evaluation_continuation",
            (0, 0, 0, 0, 0),
            f"{path}.evaluation_plan",
        )
        expected = {
            "stage": stage,
            "request_kind": request_kind,
            "evaluation_plan": plan,
            "public_request_context_digest_hex": request_digest.hex(),
            "authorization_digest_hex": authorization_digest.hex(),
            "transcript_digest_hex": transcript_digest.hex(),
        }
    else:
        common = _require_ordered_keys(
            value, EVALUATION_INPUT_PARTY_VIEWS_COMMON_KEY_ORDER, path
        )
        if provenance_pair_digest is None:
            raise VerificationError(f"{path} lacks a producing-branch provenance digest")
        if request_kind == "export":
            plan_kind = "one_export_evaluation"
            counts = (1, 1, 1, 0, 1)
        else:
            plan_kind = "one_activation_evaluation"
            counts = (1, 1, 1, 0, 2)
        plan = _verify_evaluation_input_plan(
            common["evaluation_plan"], plan_kind, counts, f"{path}.evaluation_plan"
        )
        expected = {
            "stage": stage,
            "request_kind": request_kind,
            "evaluation_plan": plan,
            "public_request_context_digest_hex": request_digest.hex(),
            "authorization_digest_hex": authorization_digest.hex(),
            "transcript_digest_hex": transcript_digest.hex(),
            "input_provenance_pair_digest_hex": provenance_pair_digest.hex(),
        }
    if common != expected:
        raise VerificationError(f"{path} differs from its independently verified companions")


def _verify_evaluation_input_empty_extension(
    value: Any, role: str, path: str
) -> None:
    extension = _require_ordered_keys(
        value, EVALUATION_INPUT_PARTY_VIEWS_EMPTY_EXTENSION_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(extension["kind"], f"{path}.kind"),
        f"{role}_empty",
        f"{path}.kind",
    )


def _verify_evaluation_input_extensions(
    value: Any,
    request_kind: str,
    expected_contributions: dict[str, dict[str, bytes]] | None,
    path: str,
) -> tuple[dict[str, Any], frozenset[str]]:
    extensions = _require_ordered_keys(
        value, EVALUATION_INPUT_PARTY_VIEWS_ROLE_EXTENSIONS_KEY_ORDER, path
    )
    private_values: set[str] = set()
    if request_kind == "activation":
        for role in EVALUATION_INPUT_PARTY_VIEWS_ROLE_EXTENSIONS_KEY_ORDER:
            kind_role = "diagnostics" if role == "diagnostics_logs" else role
            _verify_evaluation_input_empty_extension(
                extensions[role], kind_role, f"{path}.{role}"
            )
        return extensions, frozenset()

    if expected_contributions is None:
        raise VerificationError(f"{path} lacks expected role-local contributions")
    for role in ("deriver_a", "deriver_b"):
        role_path = f"{path}.{role}"
        if request_kind == "export":
            key_order = EVALUATION_INPUT_PARTY_VIEWS_EXPORT_EXTENSION_KEY_ORDER
            expected_kind = f"{role}_export_evaluation_inputs"
            field_names = ("y_client_hex", "y_server_hex")
        else:
            key_order = EVALUATION_INPUT_PARTY_VIEWS_ACTIVATION_EXTENSION_KEY_ORDER
            expected_kind = f"{role}_activation_evaluation_inputs"
            field_names = (
                "y_client_hex",
                "y_server_hex",
                "tau_client_hex",
                "tau_server_hex",
            )
        extension = _require_ordered_keys(extensions[role], key_order, role_path)
        _require_exact_value(
            _require_string(extension["kind"], f"{role_path}.kind"),
            expected_kind,
            f"{role_path}.kind",
        )
        expected = expected_contributions[role]
        for field_name in field_names:
            field_path = f"{role_path}.{field_name}"
            if field_name.startswith("tau_"):
                actual = _encode_scalar(_decode_scalar(extension[field_name], field_path))
            else:
                actual = _decode_hex(extension[field_name], 32, field_path)
            expected_name = field_name.removesuffix("_hex")
            if actual != expected[expected_name]:
                raise VerificationError(
                    f"{field_path} differs from the independently derived {request_kind} input"
                )
            private_values.add(extension[field_name])

    for role in (
        "client",
        "signing_worker",
        "router",
        "observer",
        "diagnostics_logs",
    ):
        kind_role = "diagnostics" if role == "diagnostics_logs" else role
        _verify_evaluation_input_empty_extension(
            extensions[role], kind_role, f"{path}.{role}"
        )
    return extensions, frozenset(private_values)


def _verify_evaluation_input_static_observations(
    value: Any,
    extensions: dict[str, Any],
    case_id: str,
    stage: str,
    path: str,
) -> None:
    observations = _require_ordered_keys(
        value, EVALUATION_INPUT_PARTY_VIEWS_STATIC_OBSERVATIONS_KEY_ORDER, path
    )
    for role in ("deriver_a", "deriver_b"):
        observation_path = f"{path}.{role}"
        observation = _require_ordered_keys(
            observations[role],
            EVALUATION_INPUT_PARTY_VIEWS_STATIC_OBSERVATION_KEY_ORDER,
            observation_path,
        )
        expected = {
            "observation_kind": f"static_consuming_{role}_evaluation_inputs",
            "source_case_id": case_id,
            "source_stage": stage,
            "extension": extensions[role],
        }
        extension = _require_object(
            observation["extension"], f"{observation_path}.extension"
        )
        if (
            list(observation.items()) != list(expected.items())
            or tuple(extension) != tuple(extensions[role])
        ):
            raise VerificationError(
                f"{observation_path} is not an exact copy of its consuming role extension"
            )


def _verify_evaluation_input_randomness(
    value: Any, request_kind: str, path: str
) -> tuple[bytes, ...]:
    if request_kind == "activation":
        randomness = _require_ordered_keys(
            value, EVALUATION_INPUT_PARTY_VIEWS_NO_RANDOMNESS_KEY_ORDER, path
        )
        _require_exact_value(
            _require_string(randomness["kind"], f"{path}.kind"),
            "activation_no_ideal_function_randomness",
            f"{path}.kind",
        )
        return ()
    if request_kind == "export":
        randomness = _require_ordered_keys(
            value, EVALUATION_INPUT_PARTY_VIEWS_EXPORT_RANDOMNESS_KEY_ORDER, path
        )
        _require_exact_value(
            _require_string(randomness["kind"], f"{path}.kind"),
            "export_seed_output_coin",
            f"{path}.kind",
        )
        coin = _decode_hex(
            randomness["seed_output_coin_hex"],
            32,
            f"{path}.seed_output_coin_hex",
        )
        if coin != bytes((0x77,)) * 32:
            raise VerificationError(f"{path}.seed_output_coin_hex is not the frozen coin")
        return (coin,)

    randomness = _require_ordered_keys(
        value, EVALUATION_INPUT_PARTY_VIEWS_ACTIVATION_RANDOMNESS_KEY_ORDER, path
    )
    _require_exact_value(
        _require_string(randomness["kind"], f"{path}.kind"),
        "activation_family_output_sharing_coins",
        f"{path}.kind",
    )
    client_coin = _decode_scalar(
        randomness["client_scalar_coin_hex"],
        f"{path}.client_scalar_coin_hex",
    )
    signing_worker_coin = _decode_scalar(
        randomness["signing_worker_scalar_coin_hex"],
        f"{path}.signing_worker_scalar_coin_hex",
    )
    if (client_coin, signing_worker_coin) != (3, 5):
        raise VerificationError(f"{path} does not contain the frozen activation coins")
    return (_encode_scalar(client_coin), _encode_scalar(signing_worker_coin))


def _evaluation_input_activation_outputs(
    contributions: dict[str, dict[str, bytes]],
) -> tuple[bytes, int, int]:
    role_y = tuple(
        _wrapping_add_256(
            contributions[role]["y_client"], contributions[role]["y_server"]
        )
        for role in ("deriver_a", "deriver_b")
    )
    seed = _wrapping_add_256(role_y[0], role_y[1])
    digest = hashlib.sha512(seed).digest()
    clamped = bytearray(digest[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    signing_scalar = int.from_bytes(clamped, "little") % SCALAR_ORDER
    tau = sum(
        int.from_bytes(contributions[role][field], "little")
        for role in ("deriver_a", "deriver_b")
        for field in ("tau_client", "tau_server")
    ) % SCALAR_ORDER
    return (
        seed,
        (signing_scalar + tau) % SCALAR_ORDER,
        (signing_scalar + 2 * tau) % SCALAR_ORDER,
    )


def _verify_evaluation_input_activation_output_link(
    contributions: dict[str, dict[str, bytes]],
    randomness: tuple[bytes, ...],
    output_party_vector: dict[str, Any],
    path: str,
) -> None:
    if len(randomness) != 2:
        raise VerificationError(f"{path} lacks activation ideal-function coins")
    _, x_client, x_worker = _evaluation_input_activation_outputs(contributions)
    client_coin = int.from_bytes(randomness[0], "little")
    worker_coin = int.from_bytes(randomness[1], "little")
    output_extensions = output_party_vector["role_extensions"]
    expected_shares = {
        "deriver_a": (client_coin, worker_coin),
        "deriver_b": (
            (x_client - client_coin) % SCALAR_ORDER,
            (x_worker - worker_coin) % SCALAR_ORDER,
        ),
    }
    for role, (expected_client, expected_worker) in expected_shares.items():
        extension = output_extensions[role]
        actual_client = _decode_scalar(
            extension["client_scalar_share_hex"],
            f"{path}.output_party.{role}.client_scalar_share_hex",
        )
        actual_worker = _decode_scalar(
            extension["signing_worker_scalar_share_hex"],
            f"{path}.output_party.{role}.signing_worker_scalar_share_hex",
        )
        if (actual_client, actual_worker) != (expected_client, expected_worker):
            raise VerificationError(
                f"{path} ideal coins and inputs do not reproduce {role} output shares"
            )
    common = output_party_vector["common_public"]
    if _decode_hex(common["x_client_hex"], 32, f"{path}.output_party.x_client_hex") != _compress_point(
        _multiply_base(x_client)
    ):
        raise VerificationError(f"{path} inputs do not reproduce public X_client")
    if _decode_hex(common["x_server_hex"], 32, f"{path}.output_party.x_server_hex") != _compress_point(
        _multiply_base(x_worker)
    ):
        raise VerificationError(f"{path} inputs do not reproduce public X_server")


def _verify_evaluation_input_export_output_link(
    contributions: dict[str, dict[str, bytes]],
    randomness: tuple[bytes, ...],
    output_party_vector: dict[str, Any],
    registered_public_key: bytes,
    path: str,
) -> None:
    if len(randomness) != 1:
        raise VerificationError(f"{path} lacks the export ideal-function coin")
    seed = bytes(32)
    for role in ("deriver_a", "deriver_b"):
        for field in ("y_client", "y_server"):
            seed = _wrapping_add_256(seed, contributions[role][field])
    if _derive_ed25519_public_key_from_seed(seed) != registered_public_key:
        raise VerificationError(f"{path} export inputs do not derive registered A_pub")
    coin = randomness[0]
    expected_b = _wrapping_sub_256(seed, coin)
    output_extensions = output_party_vector["role_extensions"]
    actual_a = _decode_hex(
        output_extensions["deriver_a"]["seed_share_hex"],
        32,
        f"{path}.output_party.deriver_a.seed_share_hex",
    )
    actual_b = _decode_hex(
        output_extensions["deriver_b"]["seed_share_hex"],
        32,
        f"{path}.output_party.deriver_b.seed_share_hex",
    )
    actual_seed = _decode_hex(
        output_extensions["client"]["seed_hex"],
        32,
        f"{path}.output_party.client.seed_hex",
    )
    if (actual_a, actual_b, actual_seed) != (coin, expected_b, seed):
        raise VerificationError(
            f"{path} ideal coin and inputs do not reproduce export output shares"
        )


def _evaluation_input_private_value_path_allowed(
    path: tuple[str | int, ...]
) -> bool:
    if len(path) < 5 or path[:1] != ("cases",):
        return False
    case_index = path[1]
    producing_activation_cases = {0, 2, 3}
    if case_index in producing_activation_cases:
        role_fields = {
            "y_client_hex",
            "y_server_hex",
            "tau_client_hex",
            "tau_server_hex",
        }
    elif case_index == 4:
        role_fields = {"y_client_hex", "y_server_hex"}
    else:
        role_fields = set()
    role_prefix = ("cases", case_index, "vector", "role_extensions")
    if len(path) == 6 and path[:4] == role_prefix:
        return path[4] in {"deriver_a", "deriver_b"} and path[5] in role_fields
    static_prefix = (
        "cases",
        case_index,
        "vector",
        "static_deriver_observations",
    )
    if len(path) == 7 and path[:4] == static_prefix and path[5] == "extension":
        return path[4] in {"deriver_a", "deriver_b"} and path[6] in role_fields
    randomness_prefix = (
        "cases",
        case_index,
        "vector",
        "host_only_ideal_function_randomness",
    )
    if len(path) == 5 and path[:4] == randomness_prefix:
        if case_index in producing_activation_cases:
            return path[4] in {
                "client_scalar_coin_hex",
                "signing_worker_scalar_coin_hex",
            }
        return case_index == 4 and path[4] == "seed_output_coin_hex"
    return False


def _evaluation_input_public_cryptographic_value_path(
    path: tuple[str | int, ...]
) -> bool:
    return bool(
        path
        and type(path[-1]) is str
        and (
            path[-1].endswith("_digest_hex")
            or path[-1] == "registered_public_key_hex"
        )
    )


def _evaluation_input_output_party_private_values(
    output_cases: list[Any],
) -> set[str]:
    private_values: set[str] = set()
    for index in (0, 2, 3):
        extensions = output_cases[index]["vector"]["role_extensions"]
        for role in ("deriver_a", "deriver_b"):
            private_values.update(
                {
                    extensions[role]["client_scalar_share_hex"],
                    extensions[role]["signing_worker_scalar_share_hex"],
                }
            )
    export_extensions = output_cases[4]["vector"]["role_extensions"]
    private_values.update(
        {
            export_extensions["deriver_a"]["seed_share_hex"],
            export_extensions["deriver_b"]["seed_share_hex"],
            export_extensions["client"]["seed_hex"],
        }
    )
    return private_values


def _scan_evaluation_input_private_boundary(
    value: Any,
    known_private_values: frozenset[str],
    path: tuple[str | int, ...] = (),
) -> None:
    if type(value) is dict:
        for key, nested in value.items():
            nested_path = path + (key,)
            in_view_bearing_container = (
                len(nested_path) >= 5
                and nested_path[0] == "cases"
                and nested_path[2] == "vector"
                and nested_path[3]
                in {
                    "common_public",
                    "role_extensions",
                    "static_deriver_observations",
                }
            )
            if in_view_bearing_container and (
                key in EVALUATION_INPUT_PARTY_VIEWS_FORBIDDEN_KEYS_V1
                or any(
                    key.endswith(suffix)
                    for suffix in EVALUATION_INPUT_PARTY_VIEWS_FORBIDDEN_KEY_SUFFIXES_V1
                )
            ):
                raise VerificationError(
                    f"{_output_party_path(nested_path)} is forbidden in evaluation-input party views"
                )
            _scan_evaluation_input_private_boundary(
                nested, known_private_values, nested_path
            )
        return
    if type(value) is list:
        for index, nested in enumerate(value):
            _scan_evaluation_input_private_boundary(
                nested, known_private_values, path + (index,)
            )
        return
    if (
        type(value) is str
        and value in known_private_values
        and not _evaluation_input_public_cryptographic_value_path(path)
        and not _evaluation_input_private_value_path_allowed(path)
    ):
        raise VerificationError(
            f"{_output_party_path(path)} exposes synthetic private material outside its allowed evidence path"
        )


def verify_evaluation_input_party_views_corpus(
    corpus: Any,
    ceremony_context_corpus: Any,
    provenance_corpus: Any,
    semantic_lifecycle_corpus: Any,
    output_party_views_corpus: Any,
) -> int:
    """Verifies strict host-only accepted-evaluation input custody views."""
    semantic = _verified_semantic_lifecycle_details(
        semantic_lifecycle_corpus, ceremony_context_corpus, provenance_corpus
    )
    verify_output_party_views_corpus(
        output_party_views_corpus,
        semantic_lifecycle_corpus,
        ceremony_context_corpus,
        provenance_corpus,
    )
    provenance_records = _evaluation_input_provenance_records(provenance_corpus)
    ceremony_cases = _require_object(ceremony_context_corpus, "$")["cases"]
    output_cases = _require_object(output_party_views_corpus, "$")["cases"]

    corpus_object = _require_ordered_keys(
        corpus, EVALUATION_INPUT_PARTY_VIEWS_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(corpus_object["schema"], "$.schema"),
        EVALUATION_INPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(corpus_object["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(corpus_object["evidence_scope"], "$.evidence_scope"),
        EVALUATION_INPUT_PARTY_VIEWS_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) != len(
        EVALUATION_INPUT_PARTY_VIEWS_CASE_SEQUENCE_V1
    ):
        raise VerificationError(
            "$.cases must contain exactly five evaluation-input party-view cases"
        )

    base_contributions = _evaluation_input_base_contributions(
        provenance_records["registration"]["context_binding"]
    )
    refreshed_contributions = _evaluation_input_refreshed_contributions(
        base_contributions
    )
    private_values = _evaluation_input_output_party_private_values(output_cases)
    for index, (request_kind, case_id, stage) in enumerate(
        EVALUATION_INPUT_PARTY_VIEWS_CASE_SEQUENCE_V1
    ):
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], EVALUATION_INPUT_PARTY_VIEWS_CASE_KEY_ORDER, case_path
        )
        _require_exact_value(
            _require_string(case["request_kind"], f"{case_path}.request_kind"),
            request_kind,
            f"{case_path}.request_kind",
        )
        vector_path = f"{case_path}.vector"
        vector = _require_ordered_keys(
            case["vector"], EVALUATION_INPUT_PARTY_VIEWS_VECTOR_KEY_ORDER, vector_path
        )
        _require_exact_value(
            _require_string(vector["case_id"], f"{vector_path}.case_id"),
            case_id,
            f"{vector_path}.case_id",
        )
        _require_exact_value(
            _require_string(vector["stage"], f"{vector_path}.stage"),
            stage,
            f"{vector_path}.stage",
        )
        output_vector = output_cases[index]["vector"]
        output_case_id = _require_string(
            output_vector["case_id"], f"$output_party.cases[{index}].vector.case_id"
        )

        if request_kind == "activation":
            semantic_case_id = semantic["activation_control"]["case_id"]
            activation = semantic["activation_control"]["metadata_consumed"][0][
                "activation"
            ]
            _verify_evaluation_input_source_references(
                vector["host_only_source_references"],
                request_kind,
                None,
                None,
                semantic_case_id,
                output_case_id,
                f"{vector_path}.host_only_source_references",
            )
            _verify_evaluation_input_common(
                vector["common_public"],
                request_kind,
                stage,
                activation["request_digest"],
                activation["authorization_digest"],
                activation["transcript_digest"],
                None,
                f"{vector_path}.common_public",
            )
            expected_contributions = None
        else:
            provenance = provenance_records[request_kind]
            if request_kind == "export":
                semantic_case = semantic["export"]
            else:
                semantic_case = semantic["origins"][request_kind]
            ceremony_case_id = _require_string(
                ceremony_cases[index]["vector"]["case_id"],
                f"$ceremony.cases[{index}].vector.case_id",
            )
            _verify_evaluation_input_source_references(
                vector["host_only_source_references"],
                request_kind,
                ceremony_case_id,
                provenance["case_id"],
                semantic_case["case_id"],
                output_case_id,
                f"{vector_path}.host_only_source_references",
            )
            _verify_evaluation_input_common(
                vector["common_public"],
                request_kind,
                stage,
                provenance["request_digest"],
                provenance["authorization_digest"],
                provenance["transcript_digest"],
                provenance["pair_digest"],
                f"{vector_path}.common_public",
            )
            expected_contributions = (
                refreshed_contributions
                if request_kind == "refresh"
                else base_contributions
            )

        extensions, extension_private_values = _verify_evaluation_input_extensions(
            vector["role_extensions"],
            request_kind,
            expected_contributions,
            f"{vector_path}.role_extensions",
        )
        private_values.update(extension_private_values)
        _verify_evaluation_input_static_observations(
            vector["static_deriver_observations"],
            extensions,
            case_id,
            stage,
            f"{vector_path}.static_deriver_observations",
        )
        randomness = _verify_evaluation_input_randomness(
            vector["host_only_ideal_function_randomness"],
            request_kind,
            f"{vector_path}.host_only_ideal_function_randomness",
        )
        private_values.update(value.hex() for value in randomness)
        if request_kind in SEMANTIC_LIFECYCLE_ACTIVATION_ORIGINS_V1:
            if expected_contributions is None:
                raise VerificationError(f"{vector_path} lacks activation-family inputs")
            _verify_evaluation_input_activation_output_link(
                expected_contributions, randomness, output_vector, vector_path
            )
        elif request_kind == "export":
            if expected_contributions is None:
                raise VerificationError(f"{vector_path} lacks export inputs")
            _verify_evaluation_input_export_output_link(
                expected_contributions,
                randomness,
                output_vector,
                semantic["export"]["receipt"]["registered_public_key"],
                vector_path,
            )

    _scan_evaluation_input_private_boundary(
        corpus_object,
        _known_output_party_private_values() | frozenset(private_values),
    )
    return len(cases)


def verify_uniform_abort_corpus(
    corpus: Any, ceremony_context_corpus: Any
) -> int:
    """Verifies the exact five-branch public-only host abort envelope."""
    ceremony = _verified_ceremony_encoding_map(ceremony_context_corpus)
    document = _require_ordered_keys(corpus, UNIFORM_ABORT_CORPUS_KEY_ORDER, "$")
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        UNIFORM_ABORT_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    cases = document["cases"]
    if type(cases) is not list or len(cases) != len(CEREMONY_CASE_SEQUENCE_V1):
        raise VerificationError("$.cases must contain exactly five uniform-abort cases")
    for index, (request_kind, ceremony_case_id, _) in enumerate(
        CEREMONY_CASE_SEQUENCE_V1
    ):
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], UNIFORM_ABORT_CASE_KEY_ORDER, case_path
        )
        _require_exact_value(
            _require_string(case["request_kind"], f"{case_path}.request_kind"),
            request_kind,
            f"{case_path}.request_kind",
        )
        _require_exact_value(
            _require_string(
                case["source_ceremony_case_id"],
                f"{case_path}.source_ceremony_case_id",
            ),
            ceremony_case_id,
            f"{case_path}.source_ceremony_case_id",
        )
        envelope_path = f"{case_path}.envelope"
        envelope = _require_ordered_keys(
            case["envelope"], UNIFORM_ABORT_ENVELOPE_KEY_ORDER, envelope_path
        )
        _require_exact_value(
            _require_string(
                envelope["request_kind"], f"{envelope_path}.request_kind"
            ),
            request_kind,
            f"{envelope_path}.request_kind",
        )
        transcript_digest = _decode_hex(
            envelope["public_transcript_digest_hex"],
            32,
            f"{envelope_path}.public_transcript_digest_hex",
        )
        if transcript_digest != ceremony[request_kind]["transcript_digest"]:
            raise VerificationError(
                f"{envelope_path}.public_transcript_digest_hex differs from its ceremony companion"
            )
        _require_exact_value(
            _require_string(
                envelope["public_failure_code"],
                f"{envelope_path}.public_failure_code",
            ),
            "rejected",
            f"{envelope_path}.public_failure_code",
        )
        _require_exact_value(
            _require_string(envelope["terminal"], f"{envelope_path}.terminal"),
            "aborted",
            f"{envelope_path}.terminal",
        )
    return len(cases)


def verify_evaluator_abort_view_corpus(
    corpus: Any, ceremony_context_corpus: Any
) -> int:
    """Verifies four admitted evaluator-abort state and common-only role views."""
    ceremony = _verified_ceremony_encoding_map(ceremony_context_corpus)
    document = _require_ordered_keys(
        corpus, EVALUATOR_ABORT_VIEW_CORPUS_KEY_ORDER, "$"
    )
    _require_exact_value(
        _require_string(document["schema"], "$.schema"),
        EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1,
        "$.schema",
    )
    _require_exact_value(
        _require_string(document["protocol_id"], "$.protocol_id"),
        PROTOCOL_ID_V1,
        "$.protocol_id",
    )
    _require_exact_value(
        _require_string(document["evidence_scope"], "$.evidence_scope"),
        EVALUATOR_ABORT_VIEW_VECTOR_EVIDENCE_SCOPE_V1,
        "$.evidence_scope",
    )
    expected_cases = (
        ("registration", "ceremony-registration-v1", "unregistered"),
        ("recovery", "ceremony-recovery-v1", "credential_suspended"),
        ("refresh", "ceremony-refresh-v1", "registered"),
        ("export", "ceremony-export-v1", "registered"),
    )
    cases = document["cases"]
    if type(cases) is not list or len(cases) != len(expected_cases):
        raise VerificationError(
            "$.cases must contain exactly four evaluator-abort state/party-view cases"
        )
    execution_ids: set[bytes] = set()
    for index, (request_kind, ceremony_case_id, pre_state_class) in enumerate(
        expected_cases
    ):
        case_path = f"$.cases[{index}]"
        case = _require_ordered_keys(
            cases[index], EVALUATOR_ABORT_VIEW_CASE_KEY_ORDER, case_path
        )
        _require_exact_value(
            _require_string(case["request_kind"], f"{case_path}.request_kind"),
            request_kind,
            f"{case_path}.request_kind",
        )
        _require_exact_value(
            _require_string(
                case["source_ceremony_case_id"],
                f"{case_path}.source_ceremony_case_id",
            ),
            ceremony_case_id,
            f"{case_path}.source_ceremony_case_id",
        )
        persistence_path = f"{case_path}.persistence"
        persistence = _require_ordered_keys(
            case["persistence"],
            EVALUATOR_ABORT_PERSISTENCE_KEY_ORDER,
            persistence_path,
        )
        _require_exact_value(
            _require_string(
                persistence["pre_state_class"],
                f"{persistence_path}.pre_state_class",
            ),
            pre_state_class,
            f"{persistence_path}.pre_state_class",
        )
        _require_exact_value(
            _require_string(
                persistence["transition"], f"{persistence_path}.transition"
            ),
            "self_loop",
            f"{persistence_path}.transition",
        )
        burned_path = f"{persistence_path}.burned_attempt"
        burned = _require_ordered_keys(
            persistence["burned_attempt"],
            EVALUATOR_ABORT_BURNED_ATTEMPT_KEY_ORDER,
            burned_path,
        )
        _require_exact_value(
            _require_string(burned["request_kind"], f"{burned_path}.request_kind"),
            request_kind,
            f"{burned_path}.request_kind",
        )
        burned_request = _decode_hex(
            burned["request_context_digest_hex"],
            32,
            f"{burned_path}.request_context_digest_hex",
        )
        burned_authorization = _decode_hex(
            burned["authorization_digest_hex"],
            32,
            f"{burned_path}.authorization_digest_hex",
        )
        burned_transcript = _decode_hex(
            burned["transcript_digest_hex"],
            32,
            f"{burned_path}.transcript_digest_hex",
        )
        if burned_request != ceremony[request_kind]["request_digest"]:
            raise VerificationError(f"{burned_path} request digest differs from ceremony")
        if burned_authorization != ceremony[request_kind]["authorization_digest"]:
            raise VerificationError(
                f"{burned_path} authorization digest differs from ceremony"
            )
        if burned_transcript != ceremony[request_kind]["transcript_digest"]:
            raise VerificationError(f"{burned_path} transcript digest differs from ceremony")
        execution_id = _decode_hex(
            burned["one_use_execution_id_hex"],
            32,
            f"{burned_path}.one_use_execution_id_hex",
        )
        if execution_id == bytes(32) or execution_id in execution_ids:
            raise VerificationError(
                f"{burned_path}.one_use_execution_id_hex must be nonzero and case-specific"
            )
        execution_ids.add(execution_id)

        abort_path = f"{persistence_path}.public_abort"
        abort = _require_ordered_keys(
            persistence["public_abort"],
            UNIFORM_ABORT_ENVELOPE_KEY_ORDER,
            abort_path,
        )
        _require_exact_value(
            _require_string(abort["request_kind"], f"{abort_path}.request_kind"),
            request_kind,
            f"{abort_path}.request_kind",
        )
        abort_transcript = _decode_hex(
            abort["public_transcript_digest_hex"],
            32,
            f"{abort_path}.public_transcript_digest_hex",
        )
        if abort_transcript != burned_transcript:
            raise VerificationError(
                f"{abort_path}.public_transcript_digest_hex differs from burned attempt"
            )
        _require_exact_value(
            _require_string(
                abort["public_failure_code"], f"{abort_path}.public_failure_code"
            ),
            "rejected",
            f"{abort_path}.public_failure_code",
        )
        _require_exact_value(
            _require_string(abort["terminal"], f"{abort_path}.terminal"),
            "aborted",
            f"{abort_path}.terminal",
        )

        views_path = f"{case_path}.party_views"
        views = _require_ordered_keys(
            case["party_views"], EVALUATOR_ABORT_PARTY_VIEWS_KEY_ORDER, views_path
        )
        for role in EVALUATOR_ABORT_PARTY_VIEWS_KEY_ORDER:
            view_path = f"{views_path}.{role}"
            view = _require_ordered_keys(
                views[role], UNIFORM_ABORT_ENVELOPE_KEY_ORDER, view_path
            )
            if view != abort:
                raise VerificationError(f"{view_path} must equal the exact public abort")
    return len(cases)


def verify_corpus(corpus: Any, *, differential_seed: bytes | None = None) -> int:
    """Verifies every case and returns the nonzero case count."""
    corpus_object = _require_exact_keys(corpus, {"schema", "protocol_id", "cases"}, "$")
    schema = _require_string(corpus_object["schema"], "$.schema")
    if schema != VECTOR_CORPUS_SCHEMA_V1:
        raise VerificationError(f"$.schema must equal {VECTOR_CORPUS_SCHEMA_V1!r}")
    protocol_id = _require_string(corpus_object["protocol_id"], "$.protocol_id")
    if protocol_id != PROTOCOL_ID_V1:
        raise VerificationError(f"$.protocol_id must equal {PROTOCOL_ID_V1!r}")
    cases = corpus_object["cases"]
    if type(cases) is not list or len(cases) == 0:
        raise VerificationError("$.cases must be a nonempty JSON array")
    if differential_seed is not None:
        if type(differential_seed) is not bytes or len(differential_seed) != 32:
            raise VerificationError("differential seed must contain exactly 32 bytes")
        if len(cases) > MAX_DIFFERENTIAL_CASES_V1:
            raise VerificationError(
                f"differential corpus exceeds the {MAX_DIFFERENTIAL_CASES_V1}-case v1 limit"
            )

    case_ids: set[str] = set()
    for index, case in enumerate(cases):
        case_path = f"$.cases[{index}]"
        case_object = _require_exact_keys(case, {"request_kind", "vector"}, case_path)
        request_kind = _require_string(case_object["request_kind"], f"{case_path}.request_kind")
        if request_kind not in REQUEST_KINDS:
            raise VerificationError(f"{case_path}.request_kind is unsupported")

        vector_path = f"{case_path}.vector"
        if request_kind == "export":
            export = _require_exact_keys(
                case_object["vector"], {"reference", "authorized_seed_hex"}, vector_path
            )
            if differential_seed is not None:
                _verify_differential_source(
                    export["reference"],
                    request_kind,
                    index,
                    differential_seed,
                    f"{vector_path}.reference",
                )
            joined_seed = _verify_reference(
                export["reference"], f"{vector_path}.reference", case_ids
            )
            _require_expected_bytes(
                export["authorized_seed_hex"], joined_seed, f"{vector_path}.authorized_seed_hex"
            )
        else:
            if differential_seed is not None:
                _verify_differential_source(
                    case_object["vector"],
                    request_kind,
                    index,
                    differential_seed,
                    vector_path,
                )
            _verify_reference(case_object["vector"], vector_path, case_ids)

    return len(cases)


def verify_document(
    document: Any,
    *,
    differential_seed: bytes | None = None,
    ceremony_context_corpus: Any | None = None,
    provenance_corpus: Any | None = None,
    semantic_lifecycle_corpus: Any | None = None,
    output_party_views_corpus: Any | None = None,
    activation_delivery_corpus: Any | None = None,
    activation_recipient_party_views_corpus: Any | None = None,
) -> int:
    """Auto-detects a strict v1 corpus and verifies its required companions."""
    document_object = _require_object(document, "$")
    schema = _require_string(document_object.get("schema"), "$.schema")
    if (
        ceremony_context_corpus is not None
        and schema
        not in {
            PROVENANCE_VECTOR_CORPUS_SCHEMA_V1,
            SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1,
            OUTPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            EVALUATION_INPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1,
            EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1,
            ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
            ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
        }
    ):
        raise VerificationError(
            "a ceremony-context corpus applies only to provenance or semantic-lifecycle vectors "
            "and output-party-view, evaluation-input-party-view, uniform-abort, or evaluator-abort-view vectors"
        )
    if (
        provenance_corpus is not None
        and schema
        not in {
            SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1,
            OUTPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            EVALUATION_INPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
            ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
        }
    ):
        raise VerificationError(
            "a provenance corpus applies only to semantic-lifecycle, output-party-view, "
            "and evaluation-input-party-view vectors"
        )
    if (
        semantic_lifecycle_corpus is not None
        and schema
        not in {
            OUTPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            EVALUATION_INPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
            ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
        }
    ):
        raise VerificationError(
            "a semantic-lifecycle corpus applies only to output-party-view vectors "
            "or evaluation-input-party-view vectors"
        )
    if (
        output_party_views_corpus is not None
        and schema
        not in {
            EVALUATION_INPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1,
            ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
        }
    ):
        raise VerificationError(
            "an output-party-view corpus applies only to evaluation-input-party-view or activation-delivery vectors"
        )
    if (
        activation_delivery_corpus is not None
        and schema
        not in {
            ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1,
            RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1,
        }
    ):
        raise VerificationError(
            "an activation-delivery corpus applies only to activation-recipient-party-view vectors"
        )
    if (
        activation_recipient_party_views_corpus is not None
        and schema != RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1
    ):
        raise VerificationError(
            "an activation-recipient-party-view corpus applies only to recovery credential-transition vectors"
        )
    if schema == VECTOR_CORPUS_SCHEMA_V1:
        return verify_corpus(document_object, differential_seed=differential_seed)
    if schema == KDF_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        return verify_kdf_corpus(document_object)
    if schema == LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        return verify_lifecycle_continuity_corpus(document_object)
    if schema == PROVENANCE_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if ceremony_context_corpus is None:
            raise VerificationError(
                "provenance verification requires a ceremony-context corpus"
            )
        return verify_provenance_corpus(document_object, ceremony_context_corpus)
    if schema == SEMANTIC_LIFECYCLE_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if ceremony_context_corpus is None or provenance_corpus is None:
            raise VerificationError(
                "semantic-lifecycle verification requires ceremony-context and provenance corpora"
            )
        return verify_semantic_lifecycle_corpus(
            document_object, ceremony_context_corpus, provenance_corpus
        )
    if schema == OUTPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if (
            ceremony_context_corpus is None
            or provenance_corpus is None
            or semantic_lifecycle_corpus is None
        ):
            raise VerificationError(
                "output-party-view verification requires semantic-lifecycle, "
                "ceremony-context, and provenance corpora"
            )
        return verify_output_party_views_corpus(
            document_object,
            semantic_lifecycle_corpus,
            ceremony_context_corpus,
            provenance_corpus,
        )
    if schema == EXPORT_DELIVERY_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        return verify_export_delivery_corpus(document_object)
    if schema == ACTIVATION_DELIVERY_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if (
            ceremony_context_corpus is None
            or provenance_corpus is None
            or semantic_lifecycle_corpus is None
            or output_party_views_corpus is None
        ):
            raise VerificationError(
                "activation-delivery verification requires ceremony-context, provenance, "
                "semantic-lifecycle, and output-party-view corpora"
            )
        return verify_activation_delivery_corpus(
            document_object,
            semantic_lifecycle_corpus,
            ceremony_context_corpus,
            provenance_corpus,
            output_party_views_corpus,
        )
    if schema == ACTIVATION_RECIPIENT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if (
            ceremony_context_corpus is None
            or provenance_corpus is None
            or semantic_lifecycle_corpus is None
            or output_party_views_corpus is None
            or activation_delivery_corpus is None
        ):
            raise VerificationError(
                "activation-recipient-party-view verification requires ceremony-context, "
                "provenance, semantic-lifecycle, output-party-view, and activation-delivery corpora"
            )
        return verify_activation_recipient_party_views_corpus(
            document_object,
            ceremony_context_corpus,
            provenance_corpus,
            semantic_lifecycle_corpus,
            output_party_views_corpus,
            activation_delivery_corpus,
        )
    if schema == RECOVERY_CREDENTIAL_TRANSITION_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if (
            ceremony_context_corpus is None
            or provenance_corpus is None
            or semantic_lifecycle_corpus is None
            or output_party_views_corpus is None
            or activation_delivery_corpus is None
            or activation_recipient_party_views_corpus is None
        ):
            raise VerificationError(
                "recovery credential-transition verification requires ceremony-context, provenance, "
                "semantic-lifecycle, output-party-view, activation-delivery, and activation-recipient-party-view corpora"
            )
        return verify_recovery_credential_transition_corpus(
            document_object,
            ceremony_context_corpus,
            provenance_corpus,
            semantic_lifecycle_corpus,
            output_party_views_corpus,
            activation_delivery_corpus,
            activation_recipient_party_views_corpus,
        )
    if schema == EXPORT_EVALUATOR_AUTHORIZATION_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        return verify_export_evaluator_authorization_corpus(document_object)
    if schema == REGISTRATION_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        return verify_registration_evaluator_admission_corpus(document_object)
    if schema == RECOVERY_EVALUATOR_ADMISSION_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        return verify_recovery_evaluator_admission_corpus(document_object)
    if schema == EVALUATION_INPUT_PARTY_VIEWS_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if (
            ceremony_context_corpus is None
            or provenance_corpus is None
            or semantic_lifecycle_corpus is None
            or output_party_views_corpus is None
        ):
            raise VerificationError(
                "evaluation-input-party-view verification requires ceremony-context, "
                "provenance, semantic-lifecycle, and output-party-view corpora"
            )
        return verify_evaluation_input_party_views_corpus(
            document_object,
            ceremony_context_corpus,
            provenance_corpus,
            semantic_lifecycle_corpus,
            output_party_views_corpus,
        )
    if schema == UNIFORM_ABORT_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if ceremony_context_corpus is None:
            raise VerificationError(
                "uniform-abort verification requires a ceremony-context corpus"
            )
        return verify_uniform_abort_corpus(document_object, ceremony_context_corpus)
    if schema == EVALUATOR_ABORT_VIEW_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        if ceremony_context_corpus is None:
            raise VerificationError(
                "evaluator-abort-view verification requires a ceremony-context corpus"
            )
        return verify_evaluator_abort_view_corpus(
            document_object, ceremony_context_corpus
        )
    if schema == OUTPUT_SHARING_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        return verify_output_sharing_corpus(document_object)
    if schema == CEREMONY_CONTEXT_VECTOR_CORPUS_SCHEMA_V1:
        if differential_seed is not None:
            raise VerificationError(
                "--differential-seed-hex applies only to the arithmetic vector schema"
            )
        return verify_ceremony_context_corpus(document_object)
    raise VerificationError(f"$.schema {schema!r} is unsupported")


def _parse_arguments(arguments: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Independently verify an Ed25519 Yao v1 JSON vector corpus"
    )
    parser.add_argument("corpus", type=Path, help="path to the v1 JSON vector corpus")
    parser.add_argument(
        "--differential-seed-hex",
        metavar="HEX",
        help="independently regenerate deterministic differential inputs from a 32-byte seed",
    )
    parser.add_argument(
        "--ceremony-context-corpus",
        type=Path,
        metavar="PATH",
        help=(
            "required ceremony companion for provenance, semantic-lifecycle, "
            "output-party-view, activation-delivery, activation-recipient-party-view, "
            "evaluation-input-party-view, uniform-abort, and evaluator-abort-view vectors"
        ),
    )
    parser.add_argument(
        "--provenance-corpus",
        type=Path,
        metavar="PATH",
        help=(
            "required provenance companion for semantic-lifecycle, output-party-view, "
            "activation-delivery, activation-recipient-party-view, and evaluation-input-party-view vectors"
        ),
    )
    parser.add_argument(
        "--semantic-lifecycle-corpus",
        type=Path,
        metavar="PATH",
        help=(
            "required semantic-lifecycle companion for output-party-view, activation-delivery, "
            "activation-recipient-party-view, and evaluation-input-party-view vectors"
        ),
    )
    parser.add_argument(
        "--output-party-view-corpus",
        type=Path,
        metavar="PATH",
        help=(
            "required output-party-view companion for activation-delivery, "
            "activation-recipient-party-view, and evaluation-input-party-view vectors"
        ),
    )
    parser.add_argument(
        "--activation-delivery-corpus",
        type=Path,
        metavar="PATH",
        help="required activation-delivery companion for activation-recipient-party-view vectors",
    )
    parser.add_argument(
        "--activation-recipient-party-view-corpus",
        type=Path,
        metavar="PATH",
        help="required activation-recipient companion for recovery credential-transition vectors",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parse_arguments(arguments)
    try:
        differential_seed = None
        if options.differential_seed_hex is not None:
            differential_seed = _decode_hex(
                options.differential_seed_hex, 32, "--differential-seed-hex"
            )
        document = load_corpus(options.corpus)
        ceremony_context_corpus = (
            load_corpus(options.ceremony_context_corpus)
            if options.ceremony_context_corpus is not None
            else None
        )
        provenance_corpus = (
            load_corpus(options.provenance_corpus)
            if options.provenance_corpus is not None
            else None
        )
        semantic_lifecycle_corpus = (
            load_corpus(options.semantic_lifecycle_corpus)
            if options.semantic_lifecycle_corpus is not None
            else None
        )
        output_party_views_corpus = (
            load_corpus(options.output_party_view_corpus)
            if options.output_party_view_corpus is not None
            else None
        )
        activation_delivery_corpus = (
            load_corpus(options.activation_delivery_corpus)
            if options.activation_delivery_corpus is not None
            else None
        )
        activation_recipient_party_views_corpus = (
            load_corpus(options.activation_recipient_party_view_corpus)
            if options.activation_recipient_party_view_corpus is not None
            else None
        )
        case_count = verify_document(
            document,
            differential_seed=differential_seed,
            ceremony_context_corpus=ceremony_context_corpus,
            provenance_corpus=provenance_corpus,
            semantic_lifecycle_corpus=semantic_lifecycle_corpus,
            output_party_views_corpus=output_party_views_corpus,
            activation_delivery_corpus=activation_delivery_corpus,
            activation_recipient_party_views_corpus=activation_recipient_party_views_corpus,
        )
    except VerificationError as error:
        print(f"ed25519-yao independent verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified {case_count} independent Ed25519 Yao vector cases in {options.corpus}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

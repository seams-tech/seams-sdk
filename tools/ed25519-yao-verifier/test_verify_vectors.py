#!/usr/bin/env python3
"""Mutation tests for the independent Ed25519 Yao vector verifier."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import verify_vectors


CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-v1.json"
)
DIFFERENTIAL_CORPUS_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "differential-one-case-v1.json"
)
KDF_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-kdf-v1.json"
)
LIFECYCLE_CONTINUITY_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-lifecycle-continuity-v1.json"
)
PROVENANCE_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-provenance-v1.json"
)
OUTPUT_SHARING_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-output-sharing-v1.json"
)
CEREMONY_CONTEXT_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-ceremony-context-v1.json"
)
SEMANTIC_LIFECYCLE_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-semantic-lifecycle-v1.json"
)
OUTPUT_PARTY_VIEWS_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-output-party-views-v1.json"
)
EXPORT_DELIVERY_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-export-delivery-v1.json"
)
ACTIVATION_DELIVERY_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-activation-delivery-v1.json"
)
ACTIVATION_RECIPIENT_PARTY_VIEWS_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-activation-recipient-party-views-v1.json"
)
EVALUATION_INPUT_PARTY_VIEWS_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-evaluation-input-party-views-v1.json"
)
UNIFORM_ABORT_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-uniform-abort-envelope-v1.json"
)
EVALUATOR_ABORT_VIEW_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-evaluator-abort-state-party-views-v1.json"
)
RECOVERY_CREDENTIAL_TRANSITION_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-recovery-credential-transition-v1.json"
)
EXPORT_EVALUATOR_AUTHORIZATION_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-export-evaluator-authorization-v1.json"
)
REGISTRATION_EVALUATOR_ADMISSION_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-registration-evaluator-admission-v1.json"
)
RECOVERY_EVALUATOR_ADMISSION_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-recovery-evaluator-admission-v1.json"
)
REFRESH_EVALUATOR_ADMISSION_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-refresh-evaluator-admission-v1.json"
)
DIFFERENTIAL_SEED_HEX = "5a" * 32
DIFFERENTIAL_SEED = bytes.fromhex(DIFFERENTIAL_SEED_HEX)
LIFECYCLE_PUBLIC_STATE_PATHS = (
    ("cases", 0, "vector", "pending_public"),
    ("cases", 1, "vector", "transition", "pending_public"),
    ("cases", 1, "vector", "transition", "activated_public"),
    ("cases", 2, "vector", "before_public"),
    ("cases", 2, "vector", "pending_public"),
    ("cases", 3, "vector", "transition", "pending_public"),
    ("cases", 3, "vector", "transition", "activated_public"),
    ("cases", 4, "vector", "before_public"),
    ("cases", 4, "vector", "pending_public"),
    ("cases", 5, "vector", "transition", "pending_public"),
    ("cases", 5, "vector", "transition", "activated_public"),
)


def _sign_ed25519_fixture(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    digest = bytearray(hashlib.sha512(seed).digest())
    digest[0] &= 248
    digest[31] &= 63
    digest[31] |= 64
    secret_scalar = int.from_bytes(digest[:32], "little")
    public_key = verify_vectors._derive_ed25519_public_key_from_seed(seed)
    nonce = int.from_bytes(hashlib.sha512(bytes(digest[32:]) + message).digest(), "little")
    nonce %= verify_vectors.SCALAR_ORDER
    encoded_r = verify_vectors._compress_point(verify_vectors._multiply_base(nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % verify_vectors.SCALAR_ORDER
    scalar_s = (nonce + challenge * secret_scalar) % verify_vectors.SCALAR_ORDER
    return public_key, encoded_r + scalar_s.to_bytes(32, "little")


def _reference(case: dict[str, Any]) -> dict[str, Any]:
    if case["request_kind"] == "export":
        return case["vector"]["reference"]
    return case["vector"]


def _object_at_path(document: dict[str, Any], path: tuple[str | int, ...]) -> dict[str, Any]:
    value: Any = document
    for component in path:
        value = value[component]
    if type(value) is not dict:
        raise AssertionError(f"test path {path!r} does not select an object")
    return value


def _replace_lp32_field(encoded_hex: str, index: int, replacement: bytes) -> str:
    encoded = bytearray.fromhex(encoded_hex)
    offset = 0
    for current in range(index + 1):
        length_end = offset + 4
        length = int.from_bytes(encoded[offset:length_end], "big")
        value_end = length_end + length
        if current == index:
            if len(replacement) != length:
                raise AssertionError("test replacement must preserve LP32 field length")
            encoded[length_end:value_end] = replacement
            return encoded.hex()
        offset = value_end
    raise AssertionError("test LP32 field does not exist")


def _shift_scalar_hex(encoded_hex: str, delta: int) -> str:
    scalar = int.from_bytes(bytes.fromhex(encoded_hex), "little")
    shifted = (scalar + delta) % verify_vectors.SCALAR_ORDER
    return shifted.to_bytes(32, "little").hex()


def _shift_seed_hex(encoded_hex: str, delta: int) -> str:
    seed = int.from_bytes(bytes.fromhex(encoded_hex), "little")
    shifted = (seed + delta) & verify_vectors.SEED_MODULUS_MASK
    return shifted.to_bytes(32, "little").hex()


def _lp32_join(fields: tuple[bytes, ...]) -> bytes:
    return b"".join(len(field).to_bytes(4, "big") + field for field in fields)


def _sign_ed25519(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    verifying_key = verify_vectors._compress_point(verify_vectors._multiply_base(scalar))
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little")
    nonce %= verify_vectors.SCALAR_ORDER
    encoded_r = verify_vectors._compress_point(verify_vectors._multiply_base(nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + verifying_key + message).digest(), "little"
    ) % verify_vectors.SCALAR_ORDER
    encoded_s = ((nonce + challenge * scalar) % verify_vectors.SCALAR_ORDER).to_bytes(
        32, "little"
    )
    return verifying_key, encoded_r + encoded_s


def _semantic_digest(domain: bytes, encoding: bytes) -> bytes:
    return hashlib.sha256(_lp32_join((domain, encoding))).digest()


def _coherent_semantic_registration_key_fork(
    corpus: dict[str, Any],
    ceremony_context_corpus: dict[str, Any],
    provenance_corpus: dict[str, Any],
) -> dict[str, Any]:
    mutated = copy.deepcopy(corpus)
    registration = mutated["cases"][0]["vector"]
    packages = registration["packages"]
    basepoint = verify_vectors._compress_point(verify_vectors.BASE_POINT)
    replacement_key = verify_vectors._compress_point(
        verify_vectors._point_double(verify_vectors.BASE_POINT)
    )
    descriptor_names = (
        "deriver_a_client_descriptor_encoding_hex",
        "deriver_b_client_descriptor_encoding_hex",
        "deriver_a_signing_worker_descriptor_encoding_hex",
        "deriver_b_signing_worker_descriptor_encoding_hex",
    )
    descriptor_encodings: list[bytes] = []
    for descriptor_name in descriptor_names:
        descriptor_hex = _replace_lp32_field(
            packages[descriptor_name], 15, basepoint
        )
        packages[descriptor_name] = descriptor_hex
        descriptor_encodings.append(bytes.fromhex(descriptor_hex))
    package_set_encoding = _lp32_join(
        (
            verify_vectors.ACTIVATION_PACKAGE_SET_ENCODING_DOMAIN_V1,
            *descriptor_encodings,
        )
    )
    package_set_digest = _semantic_digest(
        verify_vectors.ACTIVATION_PACKAGE_SET_DIGEST_DOMAIN_V1,
        package_set_encoding,
    )
    packages["package_set_encoding_hex"] = package_set_encoding.hex()
    packages["package_set_digest_sha256_hex"] = package_set_digest.hex()

    receipt = registration["receipt"]
    receipt_hex = receipt["receipt_body_encoding_hex"]
    for field_index, replacement in (
        (13, package_set_digest),
        (14, replacement_key),
        (15, replacement_key),
        (16, replacement_key),
    ):
        receipt_hex = _replace_lp32_field(receipt_hex, field_index, replacement)
    receipt_encoding = bytes.fromhex(receipt_hex)
    receipt_digest = _semantic_digest(
        verify_vectors.ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
        receipt_encoding,
    )
    receipt["receipt_body_encoding_hex"] = receipt_hex
    receipt["receipt_body_digest_sha256_hex"] = receipt_digest.hex()

    registration_projection = registration["persistence"]["projection"]
    registration_identity = registration_projection["identity"]
    registration_identity["package_set_digest_hex"] = package_set_digest.hex()
    registration_identity["receipt_digest_hex"] = receipt_digest.hex()
    registration_identity["registered_public_key_hex"] = replacement_key.hex()

    activation = mutated["cases"][1]["vector"]
    metadata = activation["metadata_consumed"][0]
    activation_ceremony = metadata["activation_ceremony"]
    authorization_hex = _replace_lp32_field(
        activation_ceremony["authorization_encoding_hex"],
        14,
        package_set_digest,
    )
    authorization_digest = hashlib.sha256(bytes.fromhex(authorization_hex)).digest()
    transcript_hex = _replace_lp32_field(
        activation_ceremony["transcript_encoding_hex"],
        12,
        authorization_digest,
    )
    transcript_digest = hashlib.sha256(bytes.fromhex(transcript_hex)).digest()
    activation_ceremony["authorization_encoding_hex"] = authorization_hex
    activation_ceremony["authorization_digest_sha256_hex"] = authorization_digest.hex()
    activation_ceremony["transcript_encoding_hex"] = transcript_hex
    activation_ceremony["transcript_digest_sha256_hex"] = transcript_digest.hex()
    metadata_projection = metadata["persistence"]["projection"]
    metadata_projection["committed"] = copy.deepcopy(registration_projection)
    metadata_projection["activation_authorization_digest_hex"] = authorization_digest.hex()
    metadata_projection["activation_transcript_digest_hex"] = transcript_digest.hex()

    ceremony_map = verify_vectors._verified_ceremony_encoding_map(
        ceremony_context_corpus
    )
    provenance_map = verify_vectors._verified_provenance_semantic_map(
        provenance_corpus, ceremony_context_corpus
    )
    registration_origin = verify_vectors._verify_semantic_activation_artifact_case(
        registration,
        "registration",
        ceremony_map["registration"],
        provenance_map["registration"],
        set(),
        "$test.registration",
    )
    for index, attempt in enumerate(activation["rejected_attempts"]):
        rejection_projection = attempt["persistence"]["projection"]
        rejection_projection["before"] = copy.deepcopy(registration_projection)
        rejection_projection["after"] = copy.deepcopy(registration_projection)
        attempted = verify_vectors._derive_rejected_activation_attempt(
            attempt["fresh_fields"],
            registration_origin,
            f"$test.rejected_attempts[{index}].fresh_fields",
        )
        abort = rejection_projection["abort"]
        abort["request_context_digest_hex"] = attempted["request_digest"].hex()
        abort["transcript_digest_hex"] = attempted["transcript_digest"].hex()
    return mutated


def _rewrite_provenance_request_context_digest(
    corpus: dict[str, Any], case_index: int, replacement: bytes
) -> None:
    vector = corpus["cases"][case_index]["vector"]
    vector["public_request_context_digest_hex"] = replacement.hex()
    statement_digests: list[bytes] = []
    for role_name in ("deriver_a", "deriver_b"):
        role = vector[role_name]
        ceremony_hex = _replace_lp32_field(
            role["ceremony_binding_encoding_hex"], 2, replacement
        )
        role["ceremony_binding_encoding_hex"] = ceremony_hex
        statement_hex = _replace_lp32_field(
            role["statement_encoding_hex"], 9, bytes.fromhex(ceremony_hex)
        )
        role["statement_encoding_hex"] = statement_hex
        statement_digest = hashlib.sha256(
            _lp32_join(
                (
                    verify_vectors.PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1,
                    bytes.fromhex(statement_hex),
                )
            )
        ).digest()
        role["statement_digest_sha256_hex"] = statement_digest.hex()
        statement_digests.append(statement_digest)
    pair = _lp32_join(
        (
            verify_vectors.PROVENANCE_PAIR_ENCODING_DOMAIN_V1,
            statement_digests[0],
            statement_digests[1],
        )
    )
    vector["pair_encoding_hex"] = pair.hex()
    vector["pair_digest_sha256_hex"] = hashlib.sha256(
        _lp32_join((verify_vectors.PROVENANCE_PAIR_DIGEST_DOMAIN_V1, pair))
    ).hexdigest()


def _role_epoch(root_epoch: int, input_epoch: int) -> dict[str, int]:
    return {
        "role_root_epoch": root_epoch,
        "role_input_state_epoch": input_epoch,
    }


def _role_epochs(
    a_root: int, a_input: int, b_root: int, b_input: int
) -> dict[str, dict[str, int]]:
    return {
        "deriver_a": _role_epoch(a_root, a_input),
        "deriver_b": _role_epoch(b_root, b_input),
    }


def _operation_counts(
    *,
    deriver_invocations: int,
    client_kdf_derivations: int,
    activation_evaluations: int,
    pending_consumptions: int,
) -> dict[str, int]:
    return {
        "deriver_a_invocations": deriver_invocations,
        "deriver_b_invocations": deriver_invocations,
        "client_kdf_derivations_a": client_kdf_derivations,
        "client_kdf_derivations_b": client_kdf_derivations,
        "server_kdf_derivations_a": 0,
        "server_kdf_derivations_b": 0,
        "activation_family_evaluations": activation_evaluations,
        "export_family_evaluations": 0,
        "pending_activation_consumptions": pending_consumptions,
    }


def _lifecycle_identity(kdf_case: dict[str, Any]) -> dict[str, Any]:
    trace = kdf_case["synthetic_clear_reference_trace"]
    return {
        "application_binding": copy.deepcopy(kdf_case["application_binding"]),
        "context": copy.deepcopy(kdf_case["context"]),
        "registered_public_key_hex": trace["public_key_hex"],
        "x_client_point_hex": trace["x_client_point_hex"],
        "x_server_point_hex": trace["x_server_point_hex"],
    }


def _active_state(
    identity: dict[str, Any], epochs: dict[str, Any], activation_epoch: int
) -> dict[str, Any]:
    return {
        "identity": copy.deepcopy(identity),
        "active_role_epochs": copy.deepcopy(epochs),
        "active_activation_epoch": activation_epoch,
    }


def _registration_pending_state(
    identity: dict[str, Any], epochs: dict[str, Any]
) -> dict[str, Any]:
    return {
        "identity": copy.deepcopy(identity),
        "candidate_role_epochs": copy.deepcopy(epochs),
        "pending_activation_epoch": 7,
    }


def _recovery_pending_state(
    identity: dict[str, Any], epochs: dict[str, Any]
) -> dict[str, Any]:
    return {
        "identity": copy.deepcopy(identity),
        "current_role_epochs": copy.deepcopy(epochs),
        "active_activation_epoch": 7,
        "pending_activation_epoch": 8,
    }


def _refresh_pending_state(
    identity: dict[str, Any], current_epochs: dict[str, Any], next_epochs: dict[str, Any]
) -> dict[str, Any]:
    return {
        "identity": copy.deepcopy(identity),
        "current_role_epochs": copy.deepcopy(current_epochs),
        "next_role_epochs": copy.deepcopy(next_epochs),
        "active_activation_epoch": 8,
        "pending_activation_epoch": 9,
        "derivation_admission": "frozen",
    }


def _add_le_256_hex(left: str, right: str) -> str:
    total = int.from_bytes(bytes.fromhex(left), "little") + int.from_bytes(
        bytes.fromhex(right), "little"
    )
    return (total & verify_vectors.SEED_MODULUS_MASK).to_bytes(32, "little").hex()


def _sub_le_256_hex(left: str, right: str) -> str:
    difference = int.from_bytes(bytes.fromhex(left), "little") - int.from_bytes(
        bytes.fromhex(right), "little"
    )
    return (difference & verify_vectors.SEED_MODULUS_MASK).to_bytes(32, "little").hex()


def _add_scalar_hex(value: str, delta: int) -> str:
    scalar = (int.from_bytes(bytes.fromhex(value), "little") + delta) % verify_vectors.SCALAR_ORDER
    return scalar.to_bytes(32, "little").hex()


def _different_canonical_scalar_hex(value: str) -> str:
    zero = "00" * 32
    one = "01" + "00" * 31
    return one if value == zero else zero


def _clear_reference_trace(contributions: dict[str, str]) -> dict[str, str]:
    y_a = verify_vectors._wrapping_add_256(
        bytes.fromhex(contributions["y_client_a_hex"]),
        bytes.fromhex(contributions["y_server_a_hex"]),
    )
    y_b = verify_vectors._wrapping_add_256(
        bytes.fromhex(contributions["y_client_b_hex"]),
        bytes.fromhex(contributions["y_server_b_hex"]),
    )
    joined_seed = verify_vectors._wrapping_add_256(y_a, y_b)
    sha512_digest = hashlib.sha512(joined_seed).digest()
    clamped_scalar_bytes = bytearray(sha512_digest[:32])
    clamped_scalar_bytes[0] &= 248
    clamped_scalar_bytes[31] &= 63
    clamped_scalar_bytes[31] |= 64
    clamped_scalar_bytes = bytes(clamped_scalar_bytes)
    signing_scalar = int.from_bytes(clamped_scalar_bytes, "little") % verify_vectors.SCALAR_ORDER
    tau_a = (
        int.from_bytes(bytes.fromhex(contributions["tau_client_a_hex"]), "little")
        + int.from_bytes(bytes.fromhex(contributions["tau_server_a_hex"]), "little")
    ) % verify_vectors.SCALAR_ORDER
    tau_b = (
        int.from_bytes(bytes.fromhex(contributions["tau_client_b_hex"]), "little")
        + int.from_bytes(bytes.fromhex(contributions["tau_server_b_hex"]), "little")
    ) % verify_vectors.SCALAR_ORDER
    tau = (tau_a + tau_b) % verify_vectors.SCALAR_ORDER
    x_client_base = (signing_scalar + tau) % verify_vectors.SCALAR_ORDER
    x_server_base = (signing_scalar + 2 * tau) % verify_vectors.SCALAR_ORDER
    x_client_point = verify_vectors._compress_point(
        verify_vectors._multiply_base(x_client_base)
    )
    x_server_point = verify_vectors._compress_point(
        verify_vectors._multiply_base(x_server_base)
    )
    public_key = verify_vectors._compress_point(
        verify_vectors._multiply_base(signing_scalar)
    )
    return {
        "y_a_hex": y_a.hex(),
        "y_b_hex": y_b.hex(),
        "joined_seed_hex": joined_seed.hex(),
        "sha512_digest_hex": sha512_digest.hex(),
        "clamped_scalar_bytes_hex": clamped_scalar_bytes.hex(),
        "signing_scalar_hex": signing_scalar.to_bytes(32, "little").hex(),
        "tau_a_hex": tau_a.to_bytes(32, "little").hex(),
        "tau_b_hex": tau_b.to_bytes(32, "little").hex(),
        "tau_hex": tau.to_bytes(32, "little").hex(),
        "x_client_base_hex": x_client_base.to_bytes(32, "little").hex(),
        "x_server_base_hex": x_server_base.to_bytes(32, "little").hex(),
        "x_client_point_hex": x_client_point.hex(),
        "x_server_point_hex": x_server_point.hex(),
        "public_key_hex": public_key.hex(),
    }


def _build_lifecycle_continuity_corpus(kdf_corpus: dict[str, Any]) -> dict[str, Any]:
    kdf_case = kdf_corpus["cases"][0]
    identity = _lifecycle_identity(kdf_case)
    roots = copy.deepcopy(kdf_case["synthetic_roots"])
    contributions = copy.deepcopy(kdf_case["contributions"])
    trace = copy.deepcopy(kdf_case["synthetic_clear_reference_trace"])
    current_epochs = _role_epochs(3, 11, 9, 41)
    next_epochs = _role_epochs(3, 12, 9, 43)

    registration_pending = _registration_pending_state(identity, current_epochs)
    registration = {
        "case_id": "registration_candidate_metadata_v1",
        "pending_public": copy.deepcopy(registration_pending),
        "reference_operation_counts": _operation_counts(
            deriver_invocations=0,
            client_kdf_derivations=0,
            activation_evaluations=0,
            pending_consumptions=0,
        ),
    }
    activation_after_registration = {
        "origin_kind": "registration",
        "transition": {
            "case_id": "activation_after_registration_zero_evaluation_v1",
            "origin_case_id": registration["case_id"],
            "pending_public": copy.deepcopy(registration_pending),
            "activated_public": _active_state(identity, current_epochs, 7),
            "reference_operation_counts": _operation_counts(
                deriver_invocations=0,
                client_kdf_derivations=0,
                activation_evaluations=0,
                pending_consumptions=1,
            ),
        },
    }

    recovery_pending = _recovery_pending_state(identity, current_epochs)
    recovery = {
        "case_id": "recovery_same_root_continuity_v1",
        "before_public": copy.deepcopy(
            activation_after_registration["transition"]["activated_public"]
        ),
        "pending_public": copy.deepcopy(recovery_pending),
        "reference_operation_counts": _operation_counts(
            deriver_invocations=1,
            client_kdf_derivations=1,
            activation_evaluations=1,
            pending_consumptions=0,
        ),
        "host_only_reference": {
            "synthetic_roots": roots,
            "current_contributions": copy.deepcopy(contributions),
            "recovered_client_root_hex": roots["client_root_hex"],
            "rederived_client_contributions": {
                field_name: contributions[field_name]
                for field_name in verify_vectors.LIFECYCLE_CLIENT_CONTRIBUTION_KEY_ORDER
            },
            "after_contributions": copy.deepcopy(contributions),
            "before_clear_reference_trace": copy.deepcopy(trace),
            "after_clear_reference_trace": copy.deepcopy(trace),
        },
    }
    activation_after_recovery = {
        "origin_kind": "recovery",
        "transition": {
            "case_id": "activation_after_recovery_zero_evaluation_v1",
            "origin_case_id": recovery["case_id"],
            "pending_public": copy.deepcopy(recovery_pending),
            "activated_public": _active_state(identity, current_epochs, 8),
            "reference_operation_counts": _operation_counts(
                deriver_invocations=0,
                client_kdf_derivations=0,
                activation_evaluations=0,
                pending_consumptions=1,
            ),
        },
    }

    delta_y_hex = "a5" * 32
    delta_tau = 17
    after_refresh = copy.deepcopy(contributions)
    after_refresh["y_server_a_hex"] = _add_le_256_hex(
        contributions["y_server_a_hex"], delta_y_hex
    )
    after_refresh["y_server_b_hex"] = _sub_le_256_hex(
        contributions["y_server_b_hex"], delta_y_hex
    )
    after_refresh["tau_server_a_hex"] = _add_scalar_hex(
        contributions["tau_server_a_hex"], delta_tau
    )
    after_refresh["tau_server_b_hex"] = _add_scalar_hex(
        contributions["tau_server_b_hex"], -delta_tau
    )
    refresh_pending = _refresh_pending_state(identity, current_epochs, next_epochs)
    refresh = {
        "case_id": "refresh_opposite_delta_continuity_v1",
        "before_public": _active_state(identity, current_epochs, 8),
        "pending_public": copy.deepcopy(refresh_pending),
        "reference_operation_counts": _operation_counts(
            deriver_invocations=1,
            client_kdf_derivations=0,
            activation_evaluations=1,
            pending_consumptions=0,
        ),
        "host_only_reference": {
            "synthetic_roots": copy.deepcopy(roots),
            "before_contributions": copy.deepcopy(contributions),
            "delta": {
                "deriver_a": {
                    "delta_y_hex": "3c" * 32,
                    "delta_tau_hex": (5).to_bytes(32, "little").hex(),
                },
                "deriver_b": {
                    "delta_y_hex": "69" * 32,
                    "delta_tau_hex": (12).to_bytes(32, "little").hex(),
                },
                "combined_delta_y_hex": delta_y_hex,
                "combined_delta_tau_hex": delta_tau.to_bytes(32, "little").hex(),
            },
            "after_contributions": after_refresh,
            "before_clear_reference_trace": copy.deepcopy(trace),
            "after_clear_reference_trace": _clear_reference_trace(after_refresh),
        },
    }
    activation_after_refresh = {
        "origin_kind": "refresh",
        "transition": {
            "case_id": "activation_after_refresh_zero_evaluation_v1",
            "origin_case_id": refresh["case_id"],
            "pending_public": copy.deepcopy(refresh_pending),
            "activated_public": {
                "identity": copy.deepcopy(identity),
                "active_role_epochs": copy.deepcopy(next_epochs),
                "retired_role_input_state_epochs": {
                    "deriver_a": 11,
                    "deriver_b": 41,
                },
                "active_activation_epoch": 9,
                "derivation_admission": "open",
            },
            "reference_operation_counts": _operation_counts(
                deriver_invocations=0,
                client_kdf_derivations=0,
                activation_evaluations=0,
                pending_consumptions=1,
            ),
        },
    }

    return {
        "schema": verify_vectors.LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1,
        "protocol_id": verify_vectors.PROTOCOL_ID_V1,
        "evidence_scope": verify_vectors.LIFECYCLE_CONTINUITY_EVIDENCE_SCOPE_V1,
        "cases": [
            {"request_kind": "registration", "vector": registration},
            {"request_kind": "activation", "vector": activation_after_registration},
            {"request_kind": "recovery", "vector": recovery},
            {"request_kind": "activation", "vector": activation_after_recovery},
            {"request_kind": "refresh", "vector": refresh},
            {"request_kind": "activation", "vector": activation_after_refresh},
        ],
    }


class IndependentVectorVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = verify_vectors.load_corpus(CORPUS_PATH)
        self.differential_corpus = verify_vectors.load_corpus(DIFFERENTIAL_CORPUS_PATH)
        self.kdf_corpus = verify_vectors.load_corpus(KDF_CORPUS_PATH)
        self.lifecycle_corpus = _build_lifecycle_continuity_corpus(self.kdf_corpus)
        self.provenance_corpus = verify_vectors.load_corpus(PROVENANCE_CORPUS_PATH)
        self.output_sharing_corpus = verify_vectors.load_corpus(
            OUTPUT_SHARING_CORPUS_PATH
        )
        self.ceremony_context_corpus = verify_vectors.load_corpus(
            CEREMONY_CONTEXT_CORPUS_PATH
        )
        self.semantic_lifecycle_corpus = verify_vectors.load_corpus(
            SEMANTIC_LIFECYCLE_CORPUS_PATH
        )
        self.output_party_views_corpus = verify_vectors.load_corpus(
            OUTPUT_PARTY_VIEWS_CORPUS_PATH
        )
        self.export_delivery_corpus = verify_vectors.load_corpus(
            EXPORT_DELIVERY_CORPUS_PATH
        )
        self.activation_delivery_corpus = verify_vectors.load_corpus(
            ACTIVATION_DELIVERY_CORPUS_PATH
        )
        self.activation_recipient_party_views_corpus = verify_vectors.load_corpus(
            ACTIVATION_RECIPIENT_PARTY_VIEWS_CORPUS_PATH
        )
        self.evaluation_input_party_views_corpus = verify_vectors.load_corpus(
            EVALUATION_INPUT_PARTY_VIEWS_CORPUS_PATH
        )
        self.uniform_abort_corpus = verify_vectors.load_corpus(
            UNIFORM_ABORT_CORPUS_PATH
        )
        self.evaluator_abort_view_corpus = verify_vectors.load_corpus(
            EVALUATOR_ABORT_VIEW_CORPUS_PATH
        )
        self.recovery_credential_transition_corpus = verify_vectors.load_corpus(
            RECOVERY_CREDENTIAL_TRANSITION_CORPUS_PATH
        )
        self.export_evaluator_authorization_corpus = verify_vectors.load_corpus(
            EXPORT_EVALUATOR_AUTHORIZATION_CORPUS_PATH
        )
        self.registration_evaluator_admission_corpus = verify_vectors.load_corpus(
            REGISTRATION_EVALUATOR_ADMISSION_CORPUS_PATH
        )
        self.recovery_evaluator_admission_corpus = verify_vectors.load_corpus(
            RECOVERY_EVALUATOR_ADMISSION_CORPUS_PATH
        )
        self.refresh_evaluator_admission_corpus = verify_vectors.load_corpus(
            REFRESH_EVALUATOR_ADMISSION_CORPUS_PATH
        )
        self.committed_lifecycle_corpus = (
            verify_vectors.load_corpus(LIFECYCLE_CONTINUITY_CORPUS_PATH)
            if LIFECYCLE_CONTINUITY_CORPUS_PATH.exists()
            else None
        )

    def assert_rejected(self, corpus: dict[str, Any], pattern: str) -> None:
        with self.assertRaisesRegex(verify_vectors.VerificationError, pattern):
            verify_vectors.verify_corpus(corpus)

    def assert_rejected_lifecycle(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_lifecycle_continuity_corpus(corpus)

    def assert_rejected_provenance(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_provenance_corpus(
                corpus, self.ceremony_context_corpus
            )

    def assert_rejected_output_sharing(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_output_sharing_corpus(corpus)

    def assert_rejected_ceremony_context(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_ceremony_context_corpus(corpus)

    def assert_rejected_semantic_lifecycle(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_semantic_lifecycle_corpus(
                corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            )

    def assert_rejected_output_party_views(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_output_party_views_corpus(
                corpus,
                self.semantic_lifecycle_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            )

    def assert_rejected_export_delivery(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_export_delivery_corpus(corpus)

    def assert_rejected_activation_delivery(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_activation_delivery_corpus(
                corpus,
                self.semantic_lifecycle_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
                self.output_party_views_corpus,
            )

    def assert_rejected_activation_recipient_party_views(
        self, corpus: dict[str, Any]
    ) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_activation_recipient_party_views_corpus(
                corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
                self.semantic_lifecycle_corpus,
                self.output_party_views_corpus,
                self.activation_delivery_corpus,
            )

    def assert_rejected_evaluation_input_party_views(
        self, corpus: dict[str, Any]
    ) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_evaluation_input_party_views_corpus(
                corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
                self.semantic_lifecycle_corpus,
                self.output_party_views_corpus,
            )

    def assert_rejected_uniform_abort(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_uniform_abort_corpus(
                corpus, self.ceremony_context_corpus
            )

    def assert_rejected_evaluator_abort_views(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_evaluator_abort_view_corpus(
                corpus, self.ceremony_context_corpus
            )

    def assert_rejected_recovery_credential_transition(
        self, corpus: dict[str, Any]
    ) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_recovery_credential_transition_corpus(
                corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
                self.semantic_lifecycle_corpus,
                self.output_party_views_corpus,
                self.activation_delivery_corpus,
                self.activation_recipient_party_views_corpus,
            )

    def assert_rejected_export_evaluator_authorization(
        self, corpus: dict[str, Any]
    ) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_export_evaluator_authorization_corpus(corpus)

    def assert_rejected_registration_evaluator_admission(
        self, corpus: dict[str, Any]
    ) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_registration_evaluator_admission_corpus(corpus)

    def assert_rejected_recovery_evaluator_admission(
        self, corpus: dict[str, Any]
    ) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_recovery_evaluator_admission_corpus(corpus)

    def assert_rejected_refresh_evaluator_admission(
        self, corpus: dict[str, Any]
    ) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_refresh_evaluator_admission_corpus(corpus)

    def test_committed_corpus_reproduces_all_five_cases(self) -> None:
        self.assertEqual(verify_vectors.verify_corpus(self.corpus), 5)

    def test_verifier_accepts_any_nonempty_case_count_and_case_id(self) -> None:
        single_case = copy.deepcopy(self.corpus)
        single_case["cases"] = [single_case["cases"][2]]
        _reference(single_case["cases"][0])["case_id"] = "independent_custom_case_v1"
        self.assertEqual(verify_vectors.verify_corpus(single_case), 1)

    def test_strict_parser_rejects_duplicate_keys_and_nonstandard_numbers(self) -> None:
        with self.assertRaisesRegex(verify_vectors.VerificationError, "duplicate JSON object key"):
            verify_vectors.parse_corpus_json('{"schema":"first","schema":"second"}')
        with self.assertRaisesRegex(verify_vectors.VerificationError, "non-standard JSON constant"):
            verify_vectors.parse_corpus_json('{"schema":NaN}')

    def test_unknown_fields_and_empty_corpora_are_rejected(self) -> None:
        with_unknown = copy.deepcopy(self.corpus)
        with_unknown["unknown"] = True
        self.assert_rejected(with_unknown, "invalid keys")

        empty = copy.deepcopy(self.corpus)
        empty["cases"] = []
        self.assert_rejected(empty, "nonempty JSON array")

    def test_context_encoding_binding_and_participant_order_are_checked(self) -> None:
        bad_binding = copy.deepcopy(self.corpus)
        context = _reference(bad_binding["cases"][0])["context"]
        context["binding_sha256_hex"] = "00" * 32
        self.assert_rejected(bad_binding, "binding_sha256_hex")

        unsorted = copy.deepcopy(self.corpus)
        _reference(unsorted["cases"][0])["context"]["participant_ids"] = [2, 1]
        self.assert_rejected(unsorted, "ascending order")

    def test_hex_lengths_case_and_tau_canonicality_are_checked(self) -> None:
        uppercase = copy.deepcopy(self.corpus)
        _reference(uppercase["cases"][0])["inputs"]["y_client_a_hex"] = "AA" * 32
        self.assert_rejected(uppercase, "lowercase hexadecimal")

        noncanonical_tau = copy.deepcopy(self.corpus)
        _reference(noncanonical_tau["cases"][0])["inputs"]["tau_client_a_hex"] = (
            verify_vectors.SCALAR_ORDER.to_bytes(32, "little").hex()
        )
        self.assert_rejected(noncanonical_tau, "canonical Ed25519 scalar")

    def test_seed_hash_clamp_and_scalar_mutations_are_rejected(self) -> None:
        bad_seed = copy.deepcopy(self.corpus)
        _reference(bad_seed["cases"][0])["clear_reference_trace"]["joined_seed_hex"] = "00" * 32
        self.assert_rejected(bad_seed, "joined_seed_hex")

        bad_digest = copy.deepcopy(self.corpus)
        _reference(bad_digest["cases"][0])["clear_reference_trace"]["sha512_digest_hex"] = "00" * 64
        self.assert_rejected(bad_digest, "sha512_digest_hex")

        bad_clamp = copy.deepcopy(self.corpus)
        _reference(bad_clamp["cases"][0])["clear_reference_trace"]["clamped_scalar_bytes_hex"] = (
            "00" * 32
        )
        self.assert_rejected(bad_clamp, "clamped_scalar_bytes_hex")

        bad_scalar = copy.deepcopy(self.corpus)
        _reference(bad_scalar["cases"][0])["clear_reference_trace"]["x_client_base_hex"] = "00" * 32
        self.assert_rejected(bad_scalar, "x_client_base_hex")

    def test_edwards_points_and_public_key_are_recomputed(self) -> None:
        bad_client_point = copy.deepcopy(self.corpus)
        _reference(bad_client_point["cases"][0])["clear_reference_trace"]["x_client_point_hex"] = (
            "00" * 32
        )
        self.assert_rejected(bad_client_point, "x_client_point_hex")

        bad_server_point = copy.deepcopy(self.corpus)
        _reference(bad_server_point["cases"][0])["clear_reference_trace"]["x_server_point_hex"] = (
            "00" * 32
        )
        self.assert_rejected(bad_server_point, "x_server_point_hex")

        bad_public_key = copy.deepcopy(self.corpus)
        _reference(bad_public_key["cases"][0])["clear_reference_trace"][
            "public_key_hex"
        ] = "00" * 32
        self.assert_rejected(bad_public_key, "public_key_hex")

    def test_lifecycle_tag_controls_export_only_shape(self) -> None:
        registration_as_export = copy.deepcopy(self.corpus)
        registration_as_export["cases"][0]["request_kind"] = "export"
        self.assert_rejected(registration_as_export, "invalid keys")

        export_as_activation = copy.deepcopy(self.corpus)
        export_as_activation["cases"][-1]["request_kind"] = "activation"
        self.assert_rejected(export_as_activation, "invalid keys")

        unsupported = copy.deepcopy(self.corpus)
        unsupported["cases"][0]["request_kind"] = "legacy"
        self.assert_rejected(unsupported, "unsupported")

    def test_export_seed_and_case_id_uniqueness_are_checked(self) -> None:
        bad_export = copy.deepcopy(self.corpus)
        bad_export["cases"][-1]["vector"]["authorized_seed_hex"] = "00" * 32
        self.assert_rejected(bad_export, "authorized_seed_hex")

        duplicate_id = copy.deepcopy(self.corpus)
        _reference(duplicate_id["cases"][1])["case_id"] = _reference(
            duplicate_id["cases"][0]
        )["case_id"]
        self.assert_rejected(duplicate_id, "duplicates")

    def test_round_tripped_standard_json_remains_accepted(self) -> None:
        encoded = json.dumps(self.corpus, separators=(",", ":"))
        self.assertEqual(
            verify_vectors.verify_corpus(verify_vectors.parse_corpus_json(encoded)),
            5,
        )

    def test_differential_seed_reproduces_rust_generated_input_fixture(self) -> None:
        self.assertEqual(
            verify_vectors.verify_corpus(
                self.differential_corpus, differential_seed=DIFFERENTIAL_SEED
            ),
            1,
        )
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main(
                [
                    str(DIFFERENTIAL_CORPUS_PATH),
                    "--differential-seed-hex",
                    DIFFERENTIAL_SEED_HEX,
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 1 independent", output.getvalue())

    def test_differential_seed_rejects_mutated_source_input(self) -> None:
        mutated = copy.deepcopy(self.differential_corpus)
        mutated["cases"][0]["vector"]["inputs"]["y_client_a_hex"] = "00" * 32
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            r"inputs\.y_client_a_hex does not match",
        ):
            verify_vectors.verify_corpus(mutated, differential_seed=DIFFERENTIAL_SEED)

    def test_kdf_corpus_auto_detection_reproduces_committed_continuity_case(self) -> None:
        self.assertEqual(verify_vectors.verify_kdf_corpus(self.kdf_corpus), 1)
        self.assertEqual(verify_vectors.verify_document(self.kdf_corpus), 1)
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main([str(KDF_CORPUS_PATH)])
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 1 independent", output.getvalue())

    def test_kdf_rejects_each_mutated_role_source_output(self) -> None:
        contribution_fields = self.kdf_corpus["cases"][0]["contributions"]
        for field_name in contribution_fields:
            with self.subTest(field_name=field_name):
                mutated = copy.deepcopy(self.kdf_corpus)
                mutated["cases"][0]["contributions"][field_name] = "00" * 32
                with self.assertRaisesRegex(
                    verify_vectors.VerificationError,
                    rf"contributions\.{field_name} does not match",
                ):
                    verify_vectors.verify_kdf_corpus(mutated)

    def test_kdf_recomputes_each_application_binding_fact(self) -> None:
        binding = self.kdf_corpus["cases"][0]["application_binding"]
        for field_name in (
            "wallet_id",
            "near_ed25519_signing_key_id",
            "signing_root_id",
        ):
            with self.subTest(field_name=field_name):
                mutated = copy.deepcopy(self.kdf_corpus)
                mutated["cases"][0]["application_binding"][field_name] = (
                    f"{binding[field_name]}-mutated"
                )
                self.assert_rejected_kdf(mutated, "encoded_hex")

        changed_slot = copy.deepcopy(self.kdf_corpus)
        changed_slot["cases"][0]["application_binding"]["key_creation_signer_slot"] += 1
        self.assert_rejected_kdf(changed_slot, "encoded_hex")

    def test_kdf_rejects_application_binding_encoding_and_digest_mutations(self) -> None:
        bad_encoding = copy.deepcopy(self.kdf_corpus)
        bad_encoding["cases"][0]["application_binding"]["encoded_hex"] = "00"
        self.assert_rejected_kdf(bad_encoding, "encoded_hex")

        bad_digest = copy.deepcopy(self.kdf_corpus)
        bad_digest["cases"][0]["application_binding"]["digest_sha256_hex"] = "00" * 32
        self.assert_rejected_kdf(bad_digest, "digest_sha256_hex")

    def test_kdf_rejects_noncanonical_application_binding_identifiers(self) -> None:
        for value, pattern in (
            ("", "nonempty"),
            ("wallet fixture", "visible ASCII"),
            ("wallet\x00fixture", "visible ASCII"),
            ("wallét-fixture", "visible ASCII"),
            ("\ud800", "valid Unicode scalar values"),
        ):
            with self.subTest(value=value):
                mutated = copy.deepcopy(self.kdf_corpus)
                mutated["cases"][0]["application_binding"]["wallet_id"] = value
                self.assert_rejected_kdf(mutated, pattern)

        for field_name in (
            "wallet_id",
            "near_ed25519_signing_key_id",
            "signing_root_id",
        ):
            with self.subTest(field_name=field_name):
                mutated = copy.deepcopy(self.kdf_corpus)
                mutated["cases"][0]["application_binding"][field_name] = "invalid value"
                self.assert_rejected_kdf(mutated, "visible ASCII")

        for value in (0, -1, 0x1_0000_0000, "1", True):
            with self.subTest(key_creation_signer_slot=value):
                mutated = copy.deepcopy(self.kdf_corpus)
                mutated["cases"][0]["application_binding"][
                    "key_creation_signer_slot"
                ] = value
                self.assert_rejected_kdf(mutated, "positive u32")

    def test_kdf_links_application_binding_digest_to_stable_context(self) -> None:
        mutated = copy.deepcopy(self.kdf_corpus)
        context = mutated["cases"][0]["context"]
        application_digest = bytes.fromhex("55" * 32)
        participants = context["participant_ids"]
        encoded = (
            verify_vectors.STABLE_CONTEXT_DOMAIN_V1
            + application_digest
            + participants[0].to_bytes(2, "big")
            + participants[1].to_bytes(2, "big")
        )
        context["application_binding_digest_hex"] = application_digest.hex()
        context["encoded_hex"] = encoded.hex()
        context["binding_sha256_hex"] = hashlib.sha256(
            verify_vectors.STABLE_CONTEXT_BINDING_DOMAIN_V1 + encoded
        ).hexdigest()
        self.assert_rejected_kdf(mutated, "does not match.*application_binding")

    def test_kdf_rejects_mutated_roots_context_and_joined_trace(self) -> None:
        root_fields = self.kdf_corpus["cases"][0]["synthetic_roots"]
        for field_name in root_fields:
            with self.subTest(field_name=field_name):
                mutated = copy.deepcopy(self.kdf_corpus)
                mutated["cases"][0]["synthetic_roots"][field_name] = "ff" * 32
                with self.assertRaisesRegex(
                    verify_vectors.VerificationError, r"contributions\..* does not match"
                ):
                    verify_vectors.verify_kdf_corpus(mutated)

        bad_context = copy.deepcopy(self.kdf_corpus)
        bad_context["cases"][0]["context"]["binding_sha256_hex"] = "00" * 32
        self.assert_rejected_kdf(bad_context, "binding_sha256_hex")

        bad_trace = copy.deepcopy(self.kdf_corpus)
        bad_trace["cases"][0]["synthetic_clear_reference_trace"]["public_key_hex"] = (
            "00" * 32
        )
        self.assert_rejected_kdf(bad_trace, "public_key_hex")

    def test_kdf_schema_rejects_differential_seed_mode(self) -> None:
        with self.assertRaisesRegex(
            verify_vectors.VerificationError, "applies only to the arithmetic"
        ):
            verify_vectors.verify_document(
                self.kdf_corpus, differential_seed=DIFFERENTIAL_SEED
            )

    def test_lifecycle_corpus_auto_detection_reproduces_all_six_cases(self) -> None:
        self.assertEqual(
            verify_vectors.verify_lifecycle_continuity_corpus(self.lifecycle_corpus), 6
        )
        self.assertEqual(verify_vectors.verify_document(self.lifecycle_corpus), 6)
        if self.committed_lifecycle_corpus is not None:
            self.assertEqual(
                verify_vectors.verify_lifecycle_continuity_corpus(
                    self.committed_lifecycle_corpus
                ),
                6,
            )
            self.assertEqual(self.committed_lifecycle_corpus, self.lifecycle_corpus)

    def test_lifecycle_schema_rejects_differential_seed_mode(self) -> None:
        with self.assertRaisesRegex(
            verify_vectors.VerificationError, "applies only to the arithmetic"
        ):
            verify_vectors.verify_document(
                self.lifecycle_corpus, differential_seed=DIFFERENTIAL_SEED
            )

    def test_lifecycle_parser_and_closed_shapes_reject_invalid_objects(self) -> None:
        encoded = json.dumps(self.lifecycle_corpus)
        duplicate_schema = encoded.replace(
            '"schema":',
            f'"schema":"{verify_vectors.LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1}","schema":',
            1,
        )
        with self.assertRaisesRegex(verify_vectors.VerificationError, "duplicate JSON object key"):
            verify_vectors.parse_corpus_json(duplicate_schema)

        mutations: list[tuple[str, dict[str, Any]]] = []
        unknown = copy.deepcopy(self.lifecycle_corpus)
        unknown["unknown"] = True
        mutations.append(("unknown", unknown))
        missing = copy.deepcopy(self.lifecycle_corpus)
        del missing["evidence_scope"]
        mutations.append(("missing", missing))
        null_case = copy.deepcopy(self.lifecycle_corpus)
        null_case["cases"][0]["vector"] = None
        mutations.append(("null", null_case))
        empty_case = copy.deepcopy(self.lifecycle_corpus)
        empty_case["cases"][0]["vector"] = {}
        mutations.append(("empty", empty_case))
        reordered = {
            "protocol_id": self.lifecycle_corpus["protocol_id"],
            "schema": self.lifecycle_corpus["schema"],
            "evidence_scope": self.lifecycle_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.lifecycle_corpus["cases"]),
        }
        mutations.append(("key_order", reordered))
        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_headers_count_order_and_ids_are_frozen(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        for field_name in ("schema", "protocol_id", "evidence_scope"):
            mutated = copy.deepcopy(self.lifecycle_corpus)
            mutated[field_name] = "wrong"
            mutations.append((field_name, mutated))
        too_few = copy.deepcopy(self.lifecycle_corpus)
        too_few["cases"].pop()
        mutations.append(("case_count", too_few))
        wrong_order = copy.deepcopy(self.lifecycle_corpus)
        wrong_order["cases"][0], wrong_order["cases"][2] = (
            wrong_order["cases"][2],
            wrong_order["cases"][0],
        )
        mutations.append(("case_order", wrong_order))
        wrong_id = copy.deepcopy(self.lifecycle_corpus)
        wrong_id["cases"][0]["vector"]["case_id"] = "wrong_case_v1"
        mutations.append(("case_id", wrong_id))
        duplicate_id = copy.deepcopy(self.lifecycle_corpus)
        duplicate_id["cases"][1]["vector"]["transition"]["case_id"] = duplicate_id[
            "cases"
        ][0]["vector"]["case_id"]
        mutations.append(("duplicate_case_id", duplicate_id))
        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_activation_origins_must_be_earlier_and_correctly_typed(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        missing = copy.deepcopy(self.lifecycle_corpus)
        missing["cases"][1]["vector"]["transition"]["origin_case_id"] = "missing_case_v1"
        mutations.append(("missing", missing))
        later = copy.deepcopy(self.lifecycle_corpus)
        later["cases"][1]["vector"]["transition"]["origin_case_id"] = (
            "refresh_opposite_delta_continuity_v1"
        )
        mutations.append(("later", later))
        wrong_kind = copy.deepcopy(self.lifecycle_corpus)
        wrong_kind["cases"][1]["vector"]["origin_kind"] = "refresh"
        mutations.append(("wrong_kind", wrong_kind))
        unsupported_request = copy.deepcopy(self.lifecycle_corpus)
        unsupported_request["cases"][0]["request_kind"] = "export"
        mutations.append(("unsupported_request", unsupported_request))
        unsupported_origin = copy.deepcopy(self.lifecycle_corpus)
        unsupported_origin["cases"][1]["vector"]["origin_kind"] = "activation"
        mutations.append(("unsupported_origin", unsupported_origin))
        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_activation_shape_rejects_all_secret_and_foreign_payloads(self) -> None:
        forbidden_fields = (
            "host_only_reference",
            "synthetic_roots",
            "contributions",
            "delta",
            "clear_reference_trace",
            "output_randomness",
            "registration",
            "export",
            "authorized_seed_hex",
            "optional_secrets",
            "generic_lifecycle_payload",
        )
        for case_index in (1, 3, 5):
            for field_name in forbidden_fields:
                with self.subTest(case_index=case_index, field_name=field_name):
                    mutated = copy.deepcopy(self.lifecycle_corpus)
                    mutated["cases"][case_index]["vector"]["transition"][field_name] = {}
                    self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_registration_metadata_rejects_active_state_and_drift(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        active_predecessor = copy.deepcopy(self.lifecycle_corpus)
        active_predecessor["cases"][0]["vector"]["pending_public"][
            "active_activation_epoch"
        ] = 6
        mutations.append(("active_predecessor", active_predecessor))
        host_payload = copy.deepcopy(self.lifecycle_corpus)
        host_payload["cases"][0]["vector"]["host_only_reference"] = {}
        mutations.append(("host_payload", host_payload))
        for pending_epoch in (0, True, 8):
            mutated = copy.deepcopy(self.lifecycle_corpus)
            mutated["cases"][0]["vector"]["pending_public"][
                "pending_activation_epoch"
            ] = pending_epoch
            mutations.append((f"pending_epoch_{pending_epoch!r}", mutated))
        root_epoch = copy.deepcopy(self.lifecycle_corpus)
        root_epoch["cases"][0]["vector"]["pending_public"]["candidate_role_epochs"][
            "deriver_a"
        ]["role_root_epoch"] = 4
        mutations.append(("role_root_epoch", root_epoch))
        input_epoch = copy.deepcopy(self.lifecycle_corpus)
        input_epoch["cases"][0]["vector"]["pending_public"]["candidate_role_epochs"][
            "deriver_b"
        ]["role_input_state_epoch"] = 42
        mutations.append(("role_input_epoch", input_epoch))
        identity = copy.deepcopy(self.lifecycle_corpus)
        identity["cases"][0]["vector"]["pending_public"]["identity"][
            "registered_public_key_hex"
        ] = "00" * 32
        mutations.append(("identity", identity))
        for field_name in verify_vectors.LIFECYCLE_OPERATION_COUNT_KEY_ORDER:
            mutated = copy.deepcopy(self.lifecycle_corpus)
            mutated["cases"][0]["vector"]["reference_operation_counts"][field_name] = 1
            mutations.append((f"count_{field_name}", mutated))
        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_primitives_reject_malformed_values(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        uppercase = copy.deepcopy(self.lifecycle_corpus)
        uppercase["cases"][2]["vector"]["host_only_reference"]["synthetic_roots"][
            "client_root_hex"
        ] = "AA" * 32
        mutations.append(("uppercase_hex", uppercase))
        short_hex = copy.deepcopy(self.lifecycle_corpus)
        short_hex["cases"][2]["vector"]["host_only_reference"]["synthetic_roots"][
            "client_root_hex"
        ] = "11"
        mutations.append(("short_hex", short_hex))
        noncanonical_scalar = copy.deepcopy(self.lifecycle_corpus)
        noncanonical_scalar["cases"][2]["vector"]["host_only_reference"][
            "current_contributions"
        ]["tau_client_a_hex"] = verify_vectors.SCALAR_ORDER.to_bytes(32, "little").hex()
        mutations.append(("noncanonical_scalar", noncanonical_scalar))
        zero_epoch = copy.deepcopy(self.lifecycle_corpus)
        zero_epoch["cases"][2]["vector"]["before_public"]["active_activation_epoch"] = 0
        mutations.append(("zero_epoch", zero_epoch))
        boolean_epoch = copy.deepcopy(self.lifecycle_corpus)
        boolean_epoch["cases"][2]["vector"]["before_public"]["active_activation_epoch"] = True
        mutations.append(("boolean_epoch", boolean_epoch))
        participants = copy.deepcopy(self.lifecycle_corpus)
        participants["cases"][2]["vector"]["before_public"]["identity"]["context"][
            "participant_ids"
        ] = [2, 1]
        mutations.append(("participants", participants))
        binding = copy.deepcopy(self.lifecycle_corpus)
        binding["cases"][2]["vector"]["before_public"]["identity"][
            "application_binding"
        ]["wallet_id"] = "invalid value"
        mutations.append(("application_binding", binding))
        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_recovery_rejects_changed_root_and_rederived_inputs(self) -> None:
        changed_root = copy.deepcopy(self.lifecycle_corpus)
        changed_root["cases"][2]["vector"]["host_only_reference"][
            "recovered_client_root_hex"
        ] = "12" * 32
        self.assert_rejected_lifecycle(changed_root)

        rederived_fields = verify_vectors.LIFECYCLE_CLIENT_CONTRIBUTION_KEY_ORDER
        for field_name in rederived_fields:
            with self.subTest(field_name=field_name):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][2]["vector"]["host_only_reference"][
                    "rederived_client_contributions"
                ][field_name] = "00" * 32
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_recovery_rejects_any_changed_after_contribution_or_trace(self) -> None:
        for field_name in verify_vectors.LIFECYCLE_CONTRIBUTION_KEY_ORDER:
            with self.subTest(kind="contribution", field_name=field_name):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][2]["vector"]["host_only_reference"][
                    "after_contributions"
                ][field_name] = "00" * 32
                self.assert_rejected_lifecycle(mutated)
        for field_name in verify_vectors.LIFECYCLE_TRACE_KEY_ORDER:
            with self.subTest(kind="trace", field_name=field_name):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                byte_length = 64 if field_name == "sha512_digest_hex" else 32
                mutated["cases"][2]["vector"]["host_only_reference"][
                    "after_clear_reference_trace"
                ][field_name] = "00" * byte_length
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_recovery_rejects_public_identity_and_epoch_drift(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        public_key = copy.deepcopy(self.lifecycle_corpus)
        public_key["cases"][2]["vector"]["pending_public"]["identity"][
            "registered_public_key_hex"
        ] = "00" * 32
        mutations.append(("public_key", public_key))
        root_epoch = copy.deepcopy(self.lifecycle_corpus)
        root_epoch["cases"][2]["vector"]["pending_public"]["current_role_epochs"][
            "deriver_a"
        ]["role_root_epoch"] = 4
        mutations.append(("root_epoch", root_epoch))
        input_epoch = copy.deepcopy(self.lifecycle_corpus)
        input_epoch["cases"][2]["vector"]["pending_public"]["current_role_epochs"][
            "deriver_b"
        ]["role_input_state_epoch"] = 42
        mutations.append(("input_epoch", input_epoch))
        slot = copy.deepcopy(self.lifecycle_corpus)
        slot["cases"][2]["vector"]["pending_public"]["identity"][
            "application_binding"
        ]["key_creation_signer_slot"] = 2
        mutations.append(("slot", slot))
        context = copy.deepcopy(self.lifecycle_corpus)
        context["cases"][2]["vector"]["pending_public"]["identity"]["context"][
            "binding_sha256_hex"
        ] = "00" * 32
        mutations.append(("context", context))
        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_recovery_rejects_activation_epoch_and_count_mutations(self) -> None:
        for pending_epoch in (0, 7, 6):
            with self.subTest(pending_epoch=pending_epoch):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][2]["vector"]["pending_public"][
                    "pending_activation_epoch"
                ] = pending_epoch
                self.assert_rejected_lifecycle(mutated)
        for field_name, value in (
            ("export_family_evaluations", 1),
            ("activation_family_evaluations", 0),
            ("activation_family_evaluations", 2),
        ):
            with self.subTest(field_name=field_name, value=value):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][2]["vector"]["reference_operation_counts"][
                    field_name
                ] = value
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_refresh_rejects_zero_and_noncanonical_deltas(self) -> None:
        zero_y = copy.deepcopy(self.lifecycle_corpus)
        zero_y_delta = zero_y["cases"][4]["vector"]["host_only_reference"]["delta"]
        zero_y_delta["deriver_a"]["delta_y_hex"] = "00" * 32
        zero_y_delta["deriver_b"]["delta_y_hex"] = "00" * 32
        zero_y_delta["combined_delta_y_hex"] = "00" * 32
        with self.assertRaisesRegex(
            verify_vectors.VerificationError, "combined_delta_y_hex must be nonzero"
        ):
            verify_vectors.verify_lifecycle_continuity_corpus(zero_y)
        zero_tau = copy.deepcopy(self.lifecycle_corpus)
        zero_tau_delta = zero_tau["cases"][4]["vector"]["host_only_reference"]["delta"]
        zero_tau_delta["deriver_a"]["delta_tau_hex"] = "00" * 32
        zero_tau_delta["deriver_b"]["delta_tau_hex"] = "00" * 32
        zero_tau_delta["combined_delta_tau_hex"] = "00" * 32
        with self.assertRaisesRegex(
            verify_vectors.VerificationError, "combined_delta_tau_hex must be nonzero"
        ):
            verify_vectors.verify_lifecycle_continuity_corpus(zero_tau)
        noncanonical_tau = copy.deepcopy(self.lifecycle_corpus)
        noncanonical_tau["cases"][4]["vector"]["host_only_reference"]["delta"][
            "deriver_a"
        ]["delta_tau_hex"] = verify_vectors.SCALAR_ORDER.to_bytes(32, "little").hex()
        self.assert_rejected_lifecycle(noncanonical_tau)
        noncanonical_b_tau = copy.deepcopy(self.lifecycle_corpus)
        noncanonical_b_tau["cases"][4]["vector"]["host_only_reference"]["delta"][
            "deriver_b"
        ]["delta_tau_hex"] = verify_vectors.SCALAR_ORDER.to_bytes(32, "little").hex()
        self.assert_rejected_lifecycle(noncanonical_b_tau)
        noncanonical_joint_tau = copy.deepcopy(self.lifecycle_corpus)
        noncanonical_joint_tau["cases"][4]["vector"]["host_only_reference"]["delta"][
            "combined_delta_tau_hex"
        ] = verify_vectors.SCALAR_ORDER.to_bytes(32, "little").hex()
        self.assert_rejected_lifecycle(noncanonical_joint_tau)

    def test_lifecycle_refresh_rejects_wrong_delta_application(self) -> None:
        before = self.lifecycle_corpus["cases"][4]["vector"]["host_only_reference"][
            "before_contributions"
        ]
        delta_y = self.lifecycle_corpus["cases"][4]["vector"]["host_only_reference"][
            "delta"
        ]["combined_delta_y_hex"]
        same_sign = copy.deepcopy(self.lifecycle_corpus)
        same_sign["cases"][4]["vector"]["host_only_reference"]["after_contributions"][
            "y_server_b_hex"
        ] = _add_le_256_hex(before["y_server_b_hex"], delta_y)
        self.assert_rejected_lifecycle(same_sign)
        one_sided = copy.deepcopy(self.lifecycle_corpus)
        one_sided["cases"][4]["vector"]["host_only_reference"]["after_contributions"][
            "tau_server_b_hex"
        ] = before["tau_server_b_hex"]
        self.assert_rejected_lifecycle(one_sided)
        swapped_domain = copy.deepcopy(self.lifecycle_corpus)
        swapped_domain["cases"][4]["vector"]["host_only_reference"][
            "after_contributions"
        ]["y_server_a_hex"] = _add_le_256_hex(before["y_server_a_hex"], "11" + "00" * 31)
        self.assert_rejected_lifecycle(swapped_domain)

        local_zero = copy.deepcopy(self.lifecycle_corpus)
        local_zero_delta = local_zero["cases"][4]["vector"]["host_only_reference"]["delta"]
        local_zero_delta["deriver_a"]["delta_y_hex"] = "00" * 32
        local_zero_delta["deriver_a"]["delta_tau_hex"] = "00" * 32
        local_zero_delta["deriver_b"]["delta_y_hex"] = local_zero_delta[
            "combined_delta_y_hex"
        ]
        local_zero_delta["deriver_b"]["delta_tau_hex"] = local_zero_delta[
            "combined_delta_tau_hex"
        ]
        self.assertEqual(
            verify_vectors.verify_lifecycle_continuity_corpus(local_zero), 6
        )

        wrapping = copy.deepcopy(self.lifecycle_corpus)
        wrapping_delta = wrapping["cases"][4]["vector"]["host_only_reference"]["delta"]
        wrapping_delta["deriver_a"]["delta_y_hex"] = "ff" * 32
        wrapping_delta["deriver_b"]["delta_y_hex"] = _add_le_256_hex(
            wrapping_delta["combined_delta_y_hex"], "01" + "00" * 31
        )
        wrapping_delta["deriver_a"]["delta_tau_hex"] = (
            verify_vectors.SCALAR_ORDER - 1
        ).to_bytes(32, "little").hex()
        wrapping_delta["deriver_b"]["delta_tau_hex"] = (18).to_bytes(
            32, "little"
        ).hex()
        self.assertEqual(verify_vectors.verify_lifecycle_continuity_corpus(wrapping), 6)

        outer_order = copy.deepcopy(self.lifecycle_corpus)
        outer_delta = outer_order["cases"][4]["vector"]["host_only_reference"]["delta"]
        outer_order["cases"][4]["vector"]["host_only_reference"]["delta"] = dict(
            reversed(tuple(outer_delta.items()))
        )
        with self.assertRaisesRegex(verify_vectors.VerificationError, "noncanonical key order"):
            verify_vectors.verify_lifecycle_continuity_corpus(outer_order)

        inner_order = copy.deepcopy(self.lifecycle_corpus)
        inner_delta = inner_order["cases"][4]["vector"]["host_only_reference"]["delta"]
        inner_delta["deriver_a"] = dict(reversed(tuple(inner_delta["deriver_a"].items())))
        with self.assertRaisesRegex(verify_vectors.VerificationError, "noncanonical key order"):
            verify_vectors.verify_lifecycle_continuity_corpus(inner_order)

    def test_lifecycle_refresh_rejects_client_and_trace_identity_changes(self) -> None:
        client = copy.deepcopy(self.lifecycle_corpus)
        client["cases"][4]["vector"]["host_only_reference"]["after_contributions"][
            "y_client_a_hex"
        ] = "00" * 32
        self.assert_rejected_lifecycle(client)
        for field_name in (
            "joined_seed_hex",
            "tau_hex",
            "x_client_base_hex",
            "x_server_base_hex",
            "public_key_hex",
        ):
            with self.subTest(field_name=field_name):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][4]["vector"]["host_only_reference"][
                    "after_clear_reference_trace"
                ][field_name] = "00" * 32
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_refresh_rejects_epoch_and_admission_mutations(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        root_epoch = copy.deepcopy(self.lifecycle_corpus)
        root_epoch["cases"][4]["vector"]["pending_public"]["next_role_epochs"][
            "deriver_a"
        ]["role_root_epoch"] = 4
        mutations.append(("root_epoch", root_epoch))
        for role_name, value in (("deriver_a", 11), ("deriver_b", 40), ("deriver_b", 0)):
            mutated = copy.deepcopy(self.lifecycle_corpus)
            mutated["cases"][4]["vector"]["pending_public"]["next_role_epochs"][
                role_name
            ]["role_input_state_epoch"] = value
            mutations.append((f"input_epoch_{role_name}_{value}", mutated))
        for activation_epoch in (8, 7, 0):
            mutated = copy.deepcopy(self.lifecycle_corpus)
            mutated["cases"][4]["vector"]["pending_public"][
                "pending_activation_epoch"
            ] = activation_epoch
            mutations.append((f"activation_epoch_{activation_epoch}", mutated))
        open_pending = copy.deepcopy(self.lifecycle_corpus)
        open_pending["cases"][4]["vector"]["pending_public"][
            "derivation_admission"
        ] = "open"
        mutations.append(("open_pending", open_pending))
        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_refresh_rejects_invalid_operation_counts(self) -> None:
        for field_name, value in (
            ("client_kdf_derivations_a", 1),
            ("server_kdf_derivations_b", 1),
            ("export_family_evaluations", 1),
            ("activation_family_evaluations", 0),
            ("activation_family_evaluations", 2),
        ):
            with self.subTest(field_name=field_name, value=value):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][4]["vector"]["reference_operation_counts"][
                    field_name
                ] = value
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_activation_rejects_pending_and_identity_mutations(self) -> None:
        pending = copy.deepcopy(self.lifecycle_corpus)
        pending["cases"][1]["vector"]["transition"]["pending_public"][
            "pending_activation_epoch"
        ] = 9
        self.assert_rejected_lifecycle(pending)
        public_key = copy.deepcopy(self.lifecycle_corpus)
        public_key["cases"][1]["vector"]["transition"]["activated_public"]["identity"][
            "registered_public_key_hex"
        ] = "00" * 32
        self.assert_rejected_lifecycle(public_key)
        root_epoch = copy.deepcopy(self.lifecycle_corpus)
        root_epoch["cases"][1]["vector"]["transition"]["activated_public"][
            "active_role_epochs"
        ]["deriver_a"]["role_root_epoch"] = 4
        self.assert_rejected_lifecycle(root_epoch)
        activation_epoch = copy.deepcopy(self.lifecycle_corpus)
        activation_epoch["cases"][1]["vector"]["transition"]["activated_public"][
            "active_activation_epoch"
        ] = 9
        self.assert_rejected_lifecycle(activation_epoch)
        input_epoch = copy.deepcopy(self.lifecycle_corpus)
        input_epoch["cases"][1]["vector"]["transition"]["activated_public"][
            "active_role_epochs"
        ]["deriver_b"]["role_input_state_epoch"] = 42
        self.assert_rejected_lifecycle(input_epoch)

    def test_lifecycle_refresh_activation_rejects_bad_promotion(self) -> None:
        active_epoch = copy.deepcopy(self.lifecycle_corpus)
        active_epoch["cases"][5]["vector"]["transition"]["activated_public"][
            "active_role_epochs"
        ]["deriver_a"]["role_input_state_epoch"] = 11
        self.assert_rejected_lifecycle(active_epoch)
        retired = copy.deepcopy(self.lifecycle_corpus)
        retired["cases"][5]["vector"]["transition"]["activated_public"][
            "retired_role_input_state_epochs"
        ]["deriver_b"] = 43
        self.assert_rejected_lifecycle(retired)
        admission = copy.deepcopy(self.lifecycle_corpus)
        admission["cases"][5]["vector"]["transition"]["activated_public"][
            "derivation_admission"
        ] = "frozen"
        self.assert_rejected_lifecycle(admission)

    def test_lifecycle_activation_requires_zero_evaluation_and_one_consumption(self) -> None:
        zero_fields = (
            "deriver_a_invocations",
            "deriver_b_invocations",
            "client_kdf_derivations_a",
            "client_kdf_derivations_b",
            "server_kdf_derivations_a",
            "server_kdf_derivations_b",
            "activation_family_evaluations",
            "export_family_evaluations",
        )
        for case_index in (1, 3, 5):
            for field_name in zero_fields:
                with self.subTest(case_index=case_index, field_name=field_name):
                    mutated = copy.deepcopy(self.lifecycle_corpus)
                    mutated["cases"][case_index]["vector"]["transition"][
                        "reference_operation_counts"
                    ][field_name] = 1
                    self.assert_rejected_lifecycle(mutated)
            for value in (0, 2):
                with self.subTest(case_index=case_index, consumptions=value):
                    mutated = copy.deepcopy(self.lifecycle_corpus)
                    mutated["cases"][case_index]["vector"]["transition"][
                        "reference_operation_counts"
                    ]["pending_activation_consumptions"] = value
                    self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_public_boundary_scan_rejects_every_forbidden_suffix(self) -> None:
        for path in LIFECYCLE_PUBLIC_STATE_PATHS:
            for suffix in verify_vectors.LIFECYCLE_PUBLIC_FORBIDDEN_SUFFIXES_V1:
                field_name = suffix if not suffix.startswith("_") else f"secret{suffix}"
                with self.subTest(path=path, field_name=field_name):
                    with self.assertRaises(verify_vectors.VerificationError):
                        verify_vectors._scan_lifecycle_public_boundary(
                            {"safe": {field_name: "00"}}, "$public"
                        )
                    mutated = copy.deepcopy(self.lifecycle_corpus)
                    _object_at_path(mutated, path)[field_name] = "00"
                    self.assert_rejected_lifecycle(mutated)

    def test_output_sharing_auto_detection_reproduces_all_six_cases(self) -> None:
        self.assertEqual(
            verify_vectors.verify_output_sharing_corpus(
                self.output_sharing_corpus
            ),
            6,
        )
        self.assertEqual(
            verify_vectors.verify_document(self.output_sharing_corpus), 6
        )
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main([str(OUTPUT_SHARING_CORPUS_PATH)])
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 6 independent", output.getvalue())
        with self.assertRaisesRegex(
            verify_vectors.VerificationError, "applies only to the arithmetic"
        ):
            verify_vectors.verify_document(
                self.output_sharing_corpus, differential_seed=DIFFERENTIAL_SEED
            )

    def test_output_sharing_case_order_ids_sources_and_coins_are_frozen(self) -> None:
        mutations: list[dict[str, Any]] = []

        duplicate = copy.deepcopy(self.output_sharing_corpus)
        duplicate["cases"][1] = copy.deepcopy(duplicate["cases"][0])
        mutations.append(duplicate)

        reordered = copy.deepcopy(self.output_sharing_corpus)
        reordered["cases"][0], reordered["cases"][1] = (
            reordered["cases"][1],
            reordered["cases"][0],
        )
        mutations.append(reordered)

        case_id = copy.deepcopy(self.output_sharing_corpus)
        case_id["cases"][0]["vector"]["case_id"] = "changed_case_v1"
        mutations.append(case_id)

        source = copy.deepcopy(self.output_sharing_corpus)
        source["cases"][1]["vector"]["host_only_source_reference"][
            "case_id"
        ] = "registration_rfc8032_vector_one_v1"
        mutations.append(source)

        activation_coin = copy.deepcopy(self.output_sharing_corpus)
        activation_coin["cases"][0]["vector"][
            "host_only_reference_randomness"
        ]["r_client_hex"] = "01" + "00" * 31
        mutations.append(activation_coin)

        export_coin = copy.deepcopy(self.output_sharing_corpus)
        export_coin["cases"][3]["vector"]["host_only_reference_randomness"][
            "u_hex"
        ] = "01" + "00" * 31
        mutations.append(export_coin)

        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected_output_sharing(mutated)

    def test_output_sharing_recomputes_joined_outputs_from_copied_inputs(self) -> None:
        for field_name in verify_vectors.OUTPUT_SHARING_INPUT_KEY_ORDER:
            with self.subTest(source_field=field_name):
                mutated = copy.deepcopy(self.output_sharing_corpus)
                inputs = mutated["cases"][1]["vector"][
                    "host_only_source_reference"
                ]["inputs"]
                inputs[field_name] = _different_canonical_scalar_hex(
                    inputs[field_name]
                )
                self.assert_rejected_output_sharing(mutated)

        for field_name in verify_vectors.OUTPUT_SHARING_ACTIVATION_JOINED_KEY_ORDER:
            with self.subTest(joined_field=field_name):
                mutated = copy.deepcopy(self.output_sharing_corpus)
                joined = mutated["cases"][1]["vector"][
                    "host_only_joined_outputs"
                ]
                joined[field_name] = _different_canonical_scalar_hex(
                    joined[field_name]
                )
                self.assert_rejected_output_sharing(mutated)

        export = copy.deepcopy(self.output_sharing_corpus)
        export["cases"][3]["vector"]["host_only_joined_output"][
            "joined_seed_hex"
        ] = "00" * 32
        self.assert_rejected_output_sharing(export)

    def test_output_sharing_activation_shares_match_coins_and_reconstruct(self) -> None:
        for case_index in range(3):
            for role in ("deriver_a", "deriver_b"):
                for field_name in (
                    "client_scalar_share_hex",
                    "signing_worker_scalar_share_hex",
                ):
                    with self.subTest(
                        case_index=case_index, role=role, field_name=field_name
                    ):
                        mutated = copy.deepcopy(self.output_sharing_corpus)
                        shares = mutated["cases"][case_index]["vector"][
                            "role_output_shares"
                        ][role]
                        shares[field_name] = _different_canonical_scalar_hex(
                            shares[field_name]
                        )
                        self.assert_rejected_output_sharing(mutated)

    def test_output_sharing_export_shares_reconstruct_modulo_two_to_256(self) -> None:
        for case_index in range(3, 6):
            for role in ("deriver_a", "deriver_b"):
                with self.subTest(case_index=case_index, role=role):
                    mutated = copy.deepcopy(self.output_sharing_corpus)
                    share = mutated["cases"][case_index]["vector"][
                        "role_output_shares"
                    ][role]
                    share["seed_share_hex"] = _different_canonical_scalar_hex(
                        share["seed_share_hex"]
                    )
                    self.assert_rejected_output_sharing(mutated)

    def test_output_sharing_closed_shapes_reject_invalid_structure(self) -> None:
        mutations: list[dict[str, Any]] = []

        unknown = copy.deepcopy(self.output_sharing_corpus)
        unknown["wire_encoding_hex"] = ""
        mutations.append(unknown)

        missing = copy.deepcopy(self.output_sharing_corpus)
        del missing["cases"][0]["vector"]["host_only_reference_randomness"]
        mutations.append(missing)

        null = copy.deepcopy(self.output_sharing_corpus)
        null["cases"][0]["vector"]["host_only_reference_randomness"] = None
        mutations.append(null)

        activation_seed = copy.deepcopy(self.output_sharing_corpus)
        activation_seed["cases"][0]["vector"]["role_output_shares"][
            "deriver_a"
        ]["seed_share_hex"] = "00" * 32
        mutations.append(activation_seed)

        export_scalar = copy.deepcopy(self.output_sharing_corpus)
        export_scalar["cases"][3]["vector"]["role_output_shares"][
            "deriver_a"
        ]["client_scalar_share_hex"] = "00" * 32
        mutations.append(export_scalar)

        continuation = copy.deepcopy(self.output_sharing_corpus)
        continuation["cases"][0]["vector"]["request_kind"] = "activation"
        mutations.append(continuation)

        wrong_family = copy.deepcopy(self.output_sharing_corpus)
        wrong_family["cases"][0]["output_family"] = "export"
        mutations.append(wrong_family)

        nested_reorder = copy.deepcopy(self.output_sharing_corpus)
        original_vector = nested_reorder["cases"][0]["vector"]
        nested_reorder["cases"][0]["vector"] = {
            key: copy.deepcopy(original_vector[key])
            for key in reversed(tuple(original_vector))
        }
        mutations.append(nested_reorder)

        top_reorder = {
            "protocol_id": self.output_sharing_corpus["protocol_id"],
            "schema": self.output_sharing_corpus["schema"],
            "evidence_scope": self.output_sharing_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.output_sharing_corpus["cases"]),
        }
        mutations.append(top_reorder)

        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected_output_sharing(mutated)

    def test_output_sharing_rejects_malformed_and_noncanonical_scalar_hex(self) -> None:
        mutations: list[dict[str, Any]] = []

        uppercase = copy.deepcopy(self.output_sharing_corpus)
        uppercase["cases"][0]["vector"]["host_only_joined_outputs"][
            "x_client_base_hex"
        ] = uppercase["cases"][0]["vector"]["host_only_joined_outputs"][
            "x_client_base_hex"
        ].upper()
        mutations.append(uppercase)

        short = copy.deepcopy(self.output_sharing_corpus)
        short["cases"][0]["vector"]["host_only_source_reference"]["inputs"][
            "y_client_a_hex"
        ] = "00"
        mutations.append(short)

        long = copy.deepcopy(self.output_sharing_corpus)
        long["cases"][5]["vector"]["role_output_shares"]["deriver_b"][
            "seed_share_hex"
        ] = "00" * 33
        mutations.append(long)

        scalar_order_hex = verify_vectors.SCALAR_ORDER.to_bytes(
            32, "little"
        ).hex()
        scalar_paths = (
            ("host_only_reference_randomness", "r_client_hex"),
            ("host_only_reference_randomness", "r_signing_worker_hex"),
            ("host_only_joined_outputs", "x_client_base_hex"),
            ("host_only_joined_outputs", "x_server_base_hex"),
        )
        for object_name, field_name in scalar_paths:
            mutated = copy.deepcopy(self.output_sharing_corpus)
            mutated["cases"][1]["vector"][object_name][
                field_name
            ] = scalar_order_hex
            mutations.append(mutated)
        for role in ("deriver_a", "deriver_b"):
            for field_name in (
                "client_scalar_share_hex",
                "signing_worker_scalar_share_hex",
            ):
                mutated = copy.deepcopy(self.output_sharing_corpus)
                mutated["cases"][1]["vector"]["role_output_shares"][role][
                    field_name
                ] = scalar_order_hex
                mutations.append(mutated)
        source_tau = copy.deepcopy(self.output_sharing_corpus)
        source_tau["cases"][1]["vector"]["host_only_source_reference"][
            "inputs"
        ]["tau_client_a_hex"] = scalar_order_hex
        mutations.append(source_tau)

        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected_output_sharing(mutated)

    def test_ceremony_context_rebuilds_all_five_dag_cases(self) -> None:
        self.assertEqual(
            verify_vectors.verify_ceremony_context_corpus(
                self.ceremony_context_corpus
            ),
            5,
        )
        self.assertEqual(verify_vectors.verify_document(self.ceremony_context_corpus), 5)
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main([str(CEREMONY_CONTEXT_CORPUS_PATH)])
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 5 independent", output.getvalue())

    def test_ceremony_context_rejects_version_two_and_zero_required_values(self) -> None:
        version = copy.deepcopy(self.ceremony_context_corpus)
        version["cases"][0]["vector"]["public_request_context"][
            "protocol_version"
        ] = 2
        self.assert_rejected_ceremony_context(version)

        zero_epoch = copy.deepcopy(self.ceremony_context_corpus)
        zero_epoch["cases"][3]["vector"]["authorization"][
            "next_deriver_a_input_state_epoch"
        ] = 0
        self.assert_rejected_ceremony_context(zero_epoch)

        zero_suite = copy.deepcopy(self.ceremony_context_corpus)
        zero_suite["cases"][4]["vector"]["transcript"][
            "artifact_suite_digest_hex"
        ] = "00" * 32
        self.assert_rejected_ceremony_context(zero_suite)

    def test_ceremony_context_rejects_activation_and_export_origin_kinds(self) -> None:
        for origin_kind in ("activation", "export"):
            with self.subTest(origin_kind=origin_kind):
                mutated = copy.deepcopy(self.ceremony_context_corpus)
                mutated["cases"][1]["vector"]["authorization"][
                    "origin_request_kind"
                ] = origin_kind
                self.assert_rejected_ceremony_context(mutated)

    def test_ceremony_context_rejects_current_context_as_activation_origin(self) -> None:
        mutated = copy.deepcopy(self.ceremony_context_corpus)
        activation = mutated["cases"][1]["vector"]
        activation["authorization"]["origin_request_context_digest_hex"] = (
            activation["expected"]["public_request_context_digest_sha256_hex"]
        )
        self.assert_rejected_ceremony_context(mutated)

    def test_ceremony_context_rejects_digest_edge_splicing_and_bad_export_key(self) -> None:
        authorization = copy.deepcopy(self.ceremony_context_corpus)
        authorization["cases"][2]["vector"]["expected"][
            "authorization_digest_sha256_hex"
        ] = authorization["cases"][0]["vector"]["expected"][
            "authorization_digest_sha256_hex"
        ]
        self.assert_rejected_ceremony_context(authorization)

        export = copy.deepcopy(self.ceremony_context_corpus)
        export["cases"][4]["vector"]["authorization"][
            "registered_ed25519_public_key_hex"
        ] = "01" + "00" * 31
        self.assert_rejected_ceremony_context(export)

    def test_ceremony_context_closed_shapes_and_order_are_strict(self) -> None:
        unknown = copy.deepcopy(self.ceremony_context_corpus)
        unknown["cases"][0]["vector"]["authorization"]["proof_hex"] = "00"
        self.assert_rejected_ceremony_context(unknown)

        reordered = {
            "protocol_id": self.ceremony_context_corpus["protocol_id"],
            "schema": self.ceremony_context_corpus["schema"],
            "evidence_scope": self.ceremony_context_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.ceremony_context_corpus["cases"]),
        }
        self.assert_rejected_ceremony_context(reordered)

    def test_semantic_lifecycle_auto_detection_reproduces_all_five_cases(self) -> None:
        self.assertEqual(
            verify_vectors.verify_semantic_lifecycle_corpus(
                self.semantic_lifecycle_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            ),
            5,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                self.semantic_lifecycle_corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
                provenance_corpus=self.provenance_corpus,
            ),
            5,
        )
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_document(
                self.semantic_lifecycle_corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
            )
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_document(
                self.semantic_lifecycle_corpus,
                provenance_corpus=self.provenance_corpus,
            )
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main(
                [
                    str(SEMANTIC_LIFECYCLE_CORPUS_PATH),
                    "--ceremony-context-corpus",
                    str(CEREMONY_CONTEXT_CORPUS_PATH),
                    "--provenance-corpus",
                    str(PROVENANCE_CORPUS_PATH),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 5 independent", output.getvalue())

    def test_semantic_lifecycle_headers_ids_and_public_boundary_are_strict(self) -> None:
        mutations: list[dict[str, Any]] = []
        reordered = {
            "protocol_id": self.semantic_lifecycle_corpus["protocol_id"],
            "schema": self.semantic_lifecycle_corpus["schema"],
            "evidence_scope": self.semantic_lifecycle_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.semantic_lifecycle_corpus["cases"]),
        }
        mutations.append(reordered)
        wrong_id = copy.deepcopy(self.semantic_lifecycle_corpus)
        wrong_id["cases"][0]["vector"]["case_id"] = "another-registration-case"
        mutations.append(wrong_id)
        wrong_kind = copy.deepcopy(self.semantic_lifecycle_corpus)
        wrong_kind["cases"][2]["request_kind"] = "refresh"
        mutations.append(wrong_kind)
        secret = copy.deepcopy(self.semantic_lifecycle_corpus)
        secret["cases"][0]["vector"]["joined_seed_hex"] = "00" * 32
        mutations.append(secret)
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected_semantic_lifecycle(mutated)

    def test_semantic_lifecycle_rejects_ceremony_and_package_digest_splicing(self) -> None:
        ceremony = copy.deepcopy(self.semantic_lifecycle_corpus)
        ceremony["cases"][0]["vector"]["ceremony"][
            "authorization_digest_sha256_hex"
        ] = "aa" * 32
        self.assert_rejected_semantic_lifecycle(ceremony)

        provenance = copy.deepcopy(self.semantic_lifecycle_corpus)
        descriptor = provenance["cases"][0]["vector"]["packages"]
        descriptor["deriver_a_client_descriptor_encoding_hex"] = _replace_lp32_field(
            descriptor["deriver_a_client_descriptor_encoding_hex"], 11, bytes((0xAA,)) * 32
        )
        self.assert_rejected_semantic_lifecycle(provenance)

        package_digest = copy.deepcopy(self.semantic_lifecycle_corpus)
        package_digest["cases"][2]["vector"]["packages"][
            "package_set_digest_sha256_hex"
        ] = "bb" * 32
        self.assert_rejected_semantic_lifecycle(package_digest)

        receipt_binding = copy.deepcopy(self.semantic_lifecycle_corpus)
        receipt = receipt_binding["cases"][0]["vector"]["receipt"]
        receipt["receipt_body_encoding_hex"] = _replace_lp32_field(
            receipt["receipt_body_encoding_hex"], 9, bytes((0xCC,)) * 32
        )
        self.assert_rejected_semantic_lifecycle(receipt_binding)

    def test_semantic_lifecycle_rejects_point_addition_and_public_relation_mutations(
        self,
    ) -> None:
        receipt_hex = self.semantic_lifecycle_corpus["cases"][0]["vector"]["receipt"][
            "receipt_body_encoding_hex"
        ]
        receipt_fields = verify_vectors._parse_lp32_fields(
            bytes.fromhex(receipt_hex), 19, "$test.receipt"
        )

        point_addition = copy.deepcopy(self.semantic_lifecycle_corpus)
        point_addition["cases"][0]["vector"]["receipt"][
            "receipt_body_encoding_hex"
        ] = _replace_lp32_field(receipt_hex, 14, receipt_fields[15])
        self.assert_rejected_semantic_lifecycle(point_addition)

        public_relation = copy.deepcopy(self.semantic_lifecycle_corpus)
        public_relation["cases"][0]["vector"]["receipt"][
            "receipt_body_encoding_hex"
        ] = _replace_lp32_field(receipt_hex, 16, receipt_fields[14])
        self.assert_rejected_semantic_lifecycle(public_relation)

        torsion = copy.deepcopy(self.semantic_lifecycle_corpus)
        packages = torsion["cases"][0]["vector"]["packages"]
        order_two_point = (verify_vectors.FIELD_PRIME - 1).to_bytes(32, "little")
        packages["deriver_a_client_descriptor_encoding_hex"] = _replace_lp32_field(
            packages["deriver_a_client_descriptor_encoding_hex"], 15, order_two_point
        )
        self.assert_rejected_semantic_lifecycle(torsion)

    def test_semantic_lifecycle_rejects_coherent_registration_key_fork(self) -> None:
        mutated = _coherent_semantic_registration_key_fork(
            self.semantic_lifecycle_corpus,
            self.ceremony_context_corpus,
            self.provenance_corpus,
        )
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            "registration registered key differs from export",
        ):
            verify_vectors.verify_semantic_lifecycle_corpus(
                mutated,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            )

    def test_semantic_lifecycle_persistence_cross_links_are_strict(self) -> None:
        package_digest = copy.deepcopy(self.semantic_lifecycle_corpus)
        package_digest["cases"][0]["vector"]["persistence"]["projection"][
            "identity"
        ]["package_set_digest_hex"] = "aa" * 32

        receipt_digest = copy.deepcopy(self.semantic_lifecycle_corpus)
        receipt_digest["cases"][2]["vector"]["persistence"]["projection"][
            "identity"
        ]["receipt_digest_hex"] = "bb" * 32

        activation_epoch = copy.deepcopy(self.semantic_lifecycle_corpus)
        identity = activation_epoch["cases"][3]["vector"]["persistence"][
            "projection"
        ]["identity"]
        identity["activation_epoch"] += 1

        for index, mutated in enumerate(
            (package_digest, receipt_digest, activation_epoch)
        ):
            with self.subTest(mutation=index):
                self.assert_rejected_semantic_lifecycle(mutated)

    def test_semantic_lifecycle_metadata_origins_and_zero_counters_are_strict(self) -> None:
        reordered = copy.deepcopy(self.semantic_lifecycle_corpus)
        metadata = reordered["cases"][1]["vector"]["metadata_consumed"]
        metadata[0], metadata[1] = metadata[1], metadata[0]
        self.assert_rejected_semantic_lifecycle(reordered)

        origin_case = copy.deepcopy(self.semantic_lifecycle_corpus)
        origin_case["cases"][1]["vector"]["metadata_consumed"][2][
            "origin_case_id"
        ] = origin_case["cases"][0]["vector"]["case_id"]
        self.assert_rejected_semantic_lifecycle(origin_case)

        reevaluation = copy.deepcopy(self.semantic_lifecycle_corpus)
        reevaluation["cases"][1]["vector"]["metadata_consumed"][0][
            "zero_reevaluation"
        ]["deriver_a_invocations"] = 1
        self.assert_rejected_semantic_lifecycle(reevaluation)

    def test_semantic_lifecycle_rejections_reconstruct_uniform_abort_self_loops(
        self,
    ) -> None:
        fresh = copy.deepcopy(self.semantic_lifecycle_corpus)
        fresh["cases"][1]["vector"]["rejected_attempts"][0]["fresh_fields"][
            "request_id"
        ] = "fresh-mutated-request"
        self.assert_rejected_semantic_lifecycle(fresh)

        self_loop = copy.deepcopy(self.semantic_lifecycle_corpus)
        projection = self_loop["cases"][1]["vector"]["rejected_attempts"][1][
            "persistence"
        ]["projection"]
        projection["after"]["identity"]["activation_epoch"] += 1
        self.assert_rejected_semantic_lifecycle(self_loop)

        abort_code = copy.deepcopy(self.semantic_lifecycle_corpus)
        abort_code["cases"][1]["vector"]["rejected_attempts"][2]["persistence"][
            "projection"
        ]["abort"]["public_failure_code"] = "replay_nonce_reused"
        self.assert_rejected_semantic_lifecycle(abort_code)

        ordered = copy.deepcopy(self.semantic_lifecycle_corpus)
        rejected = ordered["cases"][1]["vector"]["rejected_attempts"]
        rejected[0], rejected[1] = rejected[1], rejected[0]
        self.assert_rejected_semantic_lifecycle(ordered)

    def test_semantic_lifecycle_rejection_retains_its_registration_origin(self) -> None:
        mutated = copy.deepcopy(self.semantic_lifecycle_corpus)
        recovery_projection = copy.deepcopy(
            mutated["cases"][2]["vector"]["persistence"]["projection"]
        )
        projection = mutated["cases"][1]["vector"]["rejected_attempts"][0][
            "persistence"
        ]["projection"]
        projection["before"] = copy.deepcopy(recovery_projection)
        projection["after"] = copy.deepcopy(recovery_projection)
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            "does not match the committed artifacts",
        ):
            verify_vectors.verify_semantic_lifecycle_corpus(
                mutated,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            )

    def test_semantic_lifecycle_export_retains_state_and_rejects_secret_fields(self) -> None:
        state_effect = copy.deepcopy(self.semantic_lifecycle_corpus)
        state_effect["cases"][4]["vector"]["state_effect"] = "registered_state_deleted"
        self.assert_rejected_semantic_lifecycle(state_effect)

        secret = copy.deepcopy(self.semantic_lifecycle_corpus)
        secret["cases"][4]["vector"]["seed_share_hex"] = "00" * 32
        self.assert_rejected_semantic_lifecycle(secret)

        receipt_hex = self.semantic_lifecycle_corpus["cases"][4]["vector"]["receipt"][
            "receipt_body_encoding_hex"
        ]
        registration_receipt = self.semantic_lifecycle_corpus["cases"][0]["vector"][
            "receipt"
        ]["receipt_body_encoding_hex"]
        registration_fields = verify_vectors._parse_lp32_fields(
            bytes.fromhex(registration_receipt), 19, "$test.registration_receipt"
        )
        public_key = copy.deepcopy(self.semantic_lifecycle_corpus)
        public_key["cases"][4]["vector"]["receipt"][
            "receipt_body_encoding_hex"
        ] = _replace_lp32_field(receipt_hex, 13, registration_fields[14])
        self.assert_rejected_semantic_lifecycle(public_key)

    def test_output_party_views_auto_detection_and_cli_require_all_companions(self) -> None:
        self.assertEqual(
            verify_vectors.verify_output_party_views_corpus(
                self.output_party_views_corpus,
                self.semantic_lifecycle_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            ),
            5,
        )
        companions = {
            "semantic_lifecycle_corpus": self.semantic_lifecycle_corpus,
            "ceremony_context_corpus": self.ceremony_context_corpus,
            "provenance_corpus": self.provenance_corpus,
        }
        self.assertEqual(
            verify_vectors.verify_document(
                self.output_party_views_corpus,
                **companions,
            ),
            5,
        )
        for missing in companions:
            incomplete = dict(companions)
            del incomplete[missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(
                verify_vectors.VerificationError,
                "requires semantic-lifecycle, ceremony-context, and provenance",
            ):
                verify_vectors.verify_document(
                    self.output_party_views_corpus,
                    **incomplete,
                )
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            "semantic-lifecycle corpus applies only to output-party-view vectors",
        ):
            verify_vectors.verify_document(
                self.corpus,
                semantic_lifecycle_corpus=self.semantic_lifecycle_corpus,
            )

        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main(
                [
                    str(OUTPUT_PARTY_VIEWS_CORPUS_PATH),
                    "--semantic-lifecycle-corpus",
                    str(SEMANTIC_LIFECYCLE_CORPUS_PATH),
                    "--ceremony-context-corpus",
                    str(CEREMONY_CONTEXT_CORPUS_PATH),
                    "--provenance-corpus",
                    str(PROVENANCE_CORPUS_PATH),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 5 independent", output.getvalue())

    def test_output_party_views_headers_case_order_shapes_and_hex_are_strict(self) -> None:
        reordered = {
            "protocol_id": self.output_party_views_corpus["protocol_id"],
            "schema": self.output_party_views_corpus["schema"],
            "evidence_scope": self.output_party_views_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.output_party_views_corpus["cases"]),
        }
        wrong_case = copy.deepcopy(self.output_party_views_corpus)
        wrong_case["cases"][0]["vector"]["case_id"] = "wrong-output-view-case"
        swapped_cases = copy.deepcopy(self.output_party_views_corpus)
        swapped_cases["cases"][0], swapped_cases["cases"][2] = (
            swapped_cases["cases"][2],
            swapped_cases["cases"][0],
        )
        uppercase_share = copy.deepcopy(self.output_party_views_corpus)
        uppercase_share["cases"][0]["vector"]["role_extensions"]["deriver_a"][
            "client_scalar_share_hex"
        ] = "AA" * 32
        unknown = copy.deepcopy(self.output_party_views_corpus)
        unknown["cases"][4]["vector"]["common_public"]["activation_epoch"] = 7
        for index, mutated in enumerate(
            (reordered, wrong_case, swapped_cases, uppercase_share, unknown)
        ):
            with self.subTest(mutation=index):
                self.assert_rejected_output_party_views(mutated)
        canonical = (
            json.dumps(self.output_party_views_corpus, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
        malformed_encodings = (
            json.dumps(self.output_party_views_corpus, separators=(",", ":")).encode(
                "utf-8"
            ),
            canonical.replace(b"\n", b"\r\n"),
            b"\xef\xbb\xbf" + canonical,
            canonical[:-1],
            canonical + b"\n",
        )
        for index, malformed in enumerate(malformed_encodings):
            with self.subTest(encoding_mutation=index), patch.object(
                Path, "read_bytes", return_value=malformed
            ), self.assertRaises(verify_vectors.VerificationError):
                verify_vectors.load_corpus(OUTPUT_PARTY_VIEWS_CORPUS_PATH)

    def test_output_party_views_reject_role_recipient_stage_and_common_drift(self) -> None:
        stage = copy.deepcopy(self.output_party_views_corpus)
        stage["cases"][0]["vector"]["stage"] = "recovery_package_prepared"

        role = copy.deepcopy(self.output_party_views_corpus)
        role["cases"][0]["vector"]["common_public"]["package_projection"][
            "deriver_a_client"
        ]["role"] = "deriver_b"

        recipient = copy.deepcopy(self.output_party_views_corpus)
        recipient["cases"][0]["vector"]["common_public"]["package_projection"][
            "deriver_a_client"
        ]["recipient"] = "signing_worker"

        common = copy.deepcopy(self.output_party_views_corpus)
        common["cases"][2]["vector"]["common_public"][
            "transport_binding_digest_hex"
        ] = "44" * 32

        export_family = copy.deepcopy(self.output_party_views_corpus)
        export_family["cases"][4]["vector"]["common_public"]["package_projection"][
            "deriver_a_client"
        ]["output_family"] = "client_scalar"

        for index, mutated in enumerate((stage, role, recipient, common, export_family)):
            with self.subTest(mutation=index):
                self.assert_rejected_output_party_views(mutated)

    def test_output_party_views_reject_sum_preserving_activation_share_splice(self) -> None:
        mutated = copy.deepcopy(self.output_party_views_corpus)
        vector = mutated["cases"][0]["vector"]
        extensions = vector["role_extensions"]
        extensions["deriver_a"]["client_scalar_share_hex"] = _shift_scalar_hex(
            extensions["deriver_a"]["client_scalar_share_hex"], 1
        )
        extensions["deriver_b"]["client_scalar_share_hex"] = _shift_scalar_hex(
            extensions["deriver_b"]["client_scalar_share_hex"], -1
        )
        observations = vector["static_deriver_observations"]
        observations["deriver_a"]["extension"] = copy.deepcopy(
            extensions["deriver_a"]
        )
        observations["deriver_b"]["extension"] = copy.deepcopy(
            extensions["deriver_b"]
        )
        with self.assertRaisesRegex(
            verify_vectors.VerificationError, "descriptor point"
        ):
            verify_vectors.verify_output_party_views_corpus(
                mutated,
                self.semantic_lifecycle_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            )

    def test_output_party_views_activation_metadata_is_exact_and_zero_output(self) -> None:
        reordered = copy.deepcopy(self.output_party_views_corpus)
        projections = reordered["cases"][1]["vector"]["common_public"][
            "origin_metadata_projections"
        ]
        projections[0], projections[1] = projections[1], projections[0]

        nonzero = copy.deepcopy(self.output_party_views_corpus)
        nonzero["cases"][1]["vector"]["common_public"][
            "origin_metadata_projections"
        ][0]["zero_reevaluation"]["output_share_samples"] = 1

        private_output = copy.deepcopy(self.output_party_views_corpus)
        private_output["cases"][1]["vector"]["role_extensions"]["deriver_a"][
            "client_scalar_share_hex"
        ] = "03" + "00" * 31

        for index, mutated in enumerate((reordered, nonzero, private_output)):
            with self.subTest(mutation=index):
                self.assert_rejected_output_party_views(mutated)

    def test_output_party_views_export_reconstructs_seed_and_registered_key(self) -> None:
        bad_sum = copy.deepcopy(self.output_party_views_corpus)
        bad_sum["cases"][4]["vector"]["role_extensions"]["deriver_a"][
            "seed_share_hex"
        ] = _shift_seed_hex(
            bad_sum["cases"][4]["vector"]["role_extensions"]["deriver_a"][
                "seed_share_hex"
            ],
            1,
        )
        bad_sum["cases"][4]["vector"]["static_deriver_observations"]["deriver_a"][
            "extension"
        ] = copy.deepcopy(
            bad_sum["cases"][4]["vector"]["role_extensions"]["deriver_a"]
        )

        bad_key = copy.deepcopy(self.output_party_views_corpus)
        bad_key_vector = bad_key["cases"][4]["vector"]
        bad_key_vector["role_extensions"]["deriver_a"][
            "seed_share_hex"
        ] = _shift_seed_hex(
            bad_key_vector["role_extensions"]["deriver_a"]["seed_share_hex"], 1
        )
        bad_key_vector["role_extensions"]["client"]["seed_hex"] = _shift_seed_hex(
            bad_key_vector["role_extensions"]["client"]["seed_hex"], 1
        )
        bad_key_vector["static_deriver_observations"]["deriver_a"][
            "extension"
        ] = copy.deepcopy(bad_key_vector["role_extensions"]["deriver_a"])

        self.assert_rejected_output_party_views(bad_sum)
        with self.assertRaisesRegex(verify_vectors.VerificationError, "registered A_pub"):
            verify_vectors.verify_output_party_views_corpus(
                bad_key,
                self.semantic_lifecycle_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            )

    def test_output_party_views_export_split_equivalence_boundary_is_preserved(self) -> None:
        alternate = copy.deepcopy(self.output_party_views_corpus)
        vector = alternate["cases"][4]["vector"]
        extensions = vector["role_extensions"]
        extensions["deriver_a"]["seed_share_hex"] = _shift_seed_hex(
            extensions["deriver_a"]["seed_share_hex"], 1
        )
        extensions["deriver_b"]["seed_share_hex"] = _shift_seed_hex(
            extensions["deriver_b"]["seed_share_hex"], -1
        )
        vector["static_deriver_observations"]["deriver_a"][
            "extension"
        ] = copy.deepcopy(extensions["deriver_a"])
        vector["static_deriver_observations"]["deriver_b"][
            "extension"
        ] = copy.deepcopy(extensions["deriver_b"])
        self.assertEqual(
            verify_vectors.verify_output_party_views_corpus(
                alternate,
                self.semantic_lifecycle_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
            ),
            5,
        )

    def test_output_party_views_reject_nonexport_seed_and_router_log_private_fields(
        self,
    ) -> None:
        seed_in_registration = copy.deepcopy(self.output_party_views_corpus)
        seed_in_registration["cases"][0]["vector"]["role_extensions"]["client"][
            "seed_hex"
        ] = seed_in_registration["cases"][4]["vector"]["role_extensions"]["client"][
            "seed_hex"
        ]

        router = copy.deepcopy(self.output_party_views_corpus)
        router["cases"][0]["vector"]["role_extensions"]["router"][
            "client_scalar_share_hex"
        ] = router["cases"][0]["vector"]["role_extensions"]["deriver_a"][
            "client_scalar_share_hex"
        ]

        diagnostics = copy.deepcopy(self.output_party_views_corpus)
        diagnostics["cases"][4]["vector"]["role_extensions"]["diagnostics_logs"][
            "client_root_hex"
        ] = "11" * 32

        known_private = copy.deepcopy(self.output_party_views_corpus)
        known_private["cases"][0]["vector"]["role_extensions"]["client"][
            "x_client_base_hex"
        ] = "11" * 32

        for index, mutated in enumerate(
            (seed_in_registration, router, diagnostics, known_private)
        ):
            with self.subTest(mutation=index):
                self.assert_rejected_output_party_views(mutated)

    def test_output_party_views_static_copies_reject_peer_extension_injection(self) -> None:
        peer = copy.deepcopy(self.output_party_views_corpus)
        vector = peer["cases"][0]["vector"]
        vector["static_deriver_observations"]["deriver_a"]["extension"][
            "peer_extension"
        ] = copy.deepcopy(vector["role_extensions"]["deriver_b"])

        source_stage = copy.deepcopy(self.output_party_views_corpus)
        source_stage["cases"][2]["vector"]["static_deriver_observations"][
            "deriver_b"
        ]["source_stage"] = "registration_package_prepared"

        wrong_copy = copy.deepcopy(self.output_party_views_corpus)
        wrong_copy["cases"][3]["vector"]["static_deriver_observations"]["deriver_a"][
            "extension"
        ] = copy.deepcopy(
            wrong_copy["cases"][3]["vector"]["role_extensions"]["deriver_b"]
        )

        for index, mutated in enumerate((peer, source_stage, wrong_copy)):
            with self.subTest(mutation=index):
                self.assert_rejected_output_party_views(mutated)

    def test_evaluation_input_party_views_auto_detection_and_cli_require_companions(
        self,
    ) -> None:
        companions = {
            "ceremony_context_corpus": self.ceremony_context_corpus,
            "provenance_corpus": self.provenance_corpus,
            "semantic_lifecycle_corpus": self.semantic_lifecycle_corpus,
            "output_party_views_corpus": self.output_party_views_corpus,
        }
        self.assertEqual(
            verify_vectors.verify_evaluation_input_party_views_corpus(
                self.evaluation_input_party_views_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
                self.semantic_lifecycle_corpus,
                self.output_party_views_corpus,
            ),
            5,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                self.evaluation_input_party_views_corpus, **companions
            ),
            5,
        )
        for missing in companions:
            incomplete = dict(companions)
            del incomplete[missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(
                verify_vectors.VerificationError,
                "requires ceremony-context, provenance, semantic-lifecycle, and output-party-view",
            ):
                verify_vectors.verify_document(
                    self.evaluation_input_party_views_corpus, **incomplete
                )

        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main(
                [
                    str(EVALUATION_INPUT_PARTY_VIEWS_CORPUS_PATH),
                    "--ceremony-context-corpus",
                    str(CEREMONY_CONTEXT_CORPUS_PATH),
                    "--provenance-corpus",
                    str(PROVENANCE_CORPUS_PATH),
                    "--semantic-lifecycle-corpus",
                    str(SEMANTIC_LIFECYCLE_CORPUS_PATH),
                    "--output-party-view-corpus",
                    str(OUTPUT_PARTY_VIEWS_CORPUS_PATH),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 5 independent", output.getvalue())

    def test_evaluation_input_party_views_headers_order_and_bytes_are_strict(self) -> None:
        reordered = {
            "protocol_id": self.evaluation_input_party_views_corpus["protocol_id"],
            "schema": self.evaluation_input_party_views_corpus["schema"],
            "evidence_scope": self.evaluation_input_party_views_corpus[
                "evidence_scope"
            ],
            "cases": copy.deepcopy(
                self.evaluation_input_party_views_corpus["cases"]
            ),
        }
        wrong_case = copy.deepcopy(self.evaluation_input_party_views_corpus)
        wrong_case["cases"][0]["vector"]["case_id"] = "wrong-input-view-case"
        swapped = copy.deepcopy(self.evaluation_input_party_views_corpus)
        swapped["cases"][0], swapped["cases"][2] = (
            swapped["cases"][2],
            swapped["cases"][0],
        )
        wrong_stage = copy.deepcopy(self.evaluation_input_party_views_corpus)
        wrong_stage["cases"][3]["vector"]["stage"] = "recovery_evaluation_accepted"
        unknown = copy.deepcopy(self.evaluation_input_party_views_corpus)
        unknown["cases"][0]["vector"]["common_public"]["unknown"] = True
        for index, mutated in enumerate(
            (reordered, wrong_case, swapped, wrong_stage, unknown)
        ):
            with self.subTest(mutation=index):
                self.assert_rejected_evaluation_input_party_views(mutated)

        canonical = (
            json.dumps(
                self.evaluation_input_party_views_corpus,
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
        malformed_encodings = (
            json.dumps(
                self.evaluation_input_party_views_corpus, separators=(",", ":")
            ).encode("utf-8"),
            canonical.replace(b"\n", b"\r\n"),
            b"\xef\xbb\xbf" + canonical,
            canonical[:-1],
            canonical + b"\n",
        )
        for index, malformed in enumerate(malformed_encodings):
            with self.subTest(encoding_mutation=index), patch.object(
                Path, "read_bytes", return_value=malformed
            ), self.assertRaises(verify_vectors.VerificationError):
                verify_vectors.load_corpus(EVALUATION_INPUT_PARTY_VIEWS_CORPUS_PATH)

    def test_evaluation_input_party_views_reject_companion_and_common_drift(self) -> None:
        source = copy.deepcopy(self.evaluation_input_party_views_corpus)
        source["cases"][0]["vector"]["host_only_source_references"][
            "provenance_case_id"
        ] = "recovery_provenance_outer_v1"
        common = copy.deepcopy(self.evaluation_input_party_views_corpus)
        common["cases"][2]["vector"]["common_public"][
            "authorization_digest_hex"
        ] = "44" * 32
        activation_origin = copy.deepcopy(self.evaluation_input_party_views_corpus)
        activation_origin["cases"][1]["vector"]["host_only_source_references"][
            "activation_origin"
        ] = "recovery"
        output_source = copy.deepcopy(self.evaluation_input_party_views_corpus)
        output_source["cases"][4]["vector"]["host_only_source_references"][
            "output_party_view_case_id"
        ] = "registration_output_party_views_package_prepared_v1"
        for index, mutated in enumerate(
            (source, common, activation_origin, output_source)
        ):
            with self.subTest(mutation=index):
                self.assert_rejected_evaluation_input_party_views(mutated)

    def test_evaluation_input_party_views_reject_role_source_and_scalar_mutations(
        self,
    ) -> None:
        y = copy.deepcopy(self.evaluation_input_party_views_corpus)
        y["cases"][0]["vector"]["role_extensions"]["deriver_a"][
            "y_client_hex"
        ] = "55" * 32
        tau = copy.deepcopy(self.evaluation_input_party_views_corpus)
        tau["cases"][0]["vector"]["role_extensions"]["deriver_a"][
            "tau_client_hex"
        ] = verify_vectors.SCALAR_ORDER.to_bytes(32, "little").hex()
        swapped_roles = copy.deepcopy(self.evaluation_input_party_views_corpus)
        extensions = swapped_roles["cases"][2]["vector"]["role_extensions"]
        extensions["deriver_a"], extensions["deriver_b"] = (
            extensions["deriver_b"],
            extensions["deriver_a"],
        )
        injected_client = copy.deepcopy(self.evaluation_input_party_views_corpus)
        injected_client["cases"][0]["vector"]["role_extensions"]["client"][
            "y_client_hex"
        ] = "33" * 32
        for index, mutated in enumerate((y, tau, swapped_roles, injected_client)):
            with self.subTest(mutation=index):
                self.assert_rejected_evaluation_input_party_views(mutated)

    def test_evaluation_input_party_views_enforce_recovery_and_refresh_relations(
        self,
    ) -> None:
        recovery = copy.deepcopy(self.evaluation_input_party_views_corpus)
        recovery["cases"][2]["vector"]["role_extensions"]["deriver_b"][
            "y_server_hex"
        ] = _shift_seed_hex(
            recovery["cases"][2]["vector"]["role_extensions"]["deriver_b"][
                "y_server_hex"
            ],
            1,
        )
        refresh_y = copy.deepcopy(self.evaluation_input_party_views_corpus)
        refresh_y["cases"][3]["vector"]["role_extensions"]["deriver_a"][
            "y_server_hex"
        ] = _shift_seed_hex(
            refresh_y["cases"][3]["vector"]["role_extensions"]["deriver_a"][
                "y_server_hex"
            ],
            1,
        )
        refresh_tau = copy.deepcopy(self.evaluation_input_party_views_corpus)
        refresh_tau["cases"][3]["vector"]["role_extensions"]["deriver_b"][
            "tau_server_hex"
        ] = _shift_scalar_hex(
            refresh_tau["cases"][3]["vector"]["role_extensions"]["deriver_b"][
                "tau_server_hex"
            ],
            1,
        )
        for index, mutated in enumerate((recovery, refresh_y, refresh_tau)):
            with self.subTest(mutation=index):
                self.assert_rejected_evaluation_input_party_views(mutated)

    def test_evaluation_input_party_views_activation_is_zero_work_and_empty(self) -> None:
        work = copy.deepcopy(self.evaluation_input_party_views_corpus)
        work["cases"][1]["vector"]["common_public"]["evaluation_plan"]["counts"][
            "yao_evaluations"
        ] = 1
        input_value = copy.deepcopy(self.evaluation_input_party_views_corpus)
        input_value["cases"][1]["vector"]["role_extensions"]["deriver_a"][
            "y_client_hex"
        ] = "11" * 32
        randomness = copy.deepcopy(self.evaluation_input_party_views_corpus)
        randomness["cases"][1]["vector"]["host_only_ideal_function_randomness"][
            "seed_output_coin_hex"
        ] = "77" * 32
        provenance = copy.deepcopy(self.evaluation_input_party_views_corpus)
        provenance["cases"][1]["vector"]["common_public"][
            "input_provenance_pair_digest_hex"
        ] = "22" * 32
        for index, mutated in enumerate((work, input_value, randomness, provenance)):
            with self.subTest(mutation=index):
                self.assert_rejected_evaluation_input_party_views(mutated)

    def test_evaluation_input_party_views_export_is_y_only_with_one_seed_coin(self) -> None:
        tau = copy.deepcopy(self.evaluation_input_party_views_corpus)
        tau["cases"][4]["vector"]["role_extensions"]["deriver_a"][
            "tau_client_hex"
        ] = "00" * 32
        wrong_plan = copy.deepcopy(self.evaluation_input_party_views_corpus)
        wrong_plan["cases"][4]["vector"]["common_public"]["evaluation_plan"][
            "counts"
        ]["ideal_output_share_samples"] = 2
        wrong_coin = copy.deepcopy(self.evaluation_input_party_views_corpus)
        wrong_coin["cases"][4]["vector"]["host_only_ideal_function_randomness"][
            "seed_output_coin_hex"
        ] = "76" * 32
        activation_coin = copy.deepcopy(self.evaluation_input_party_views_corpus)
        activation_coin["cases"][4]["vector"][
            "host_only_ideal_function_randomness"
        ]["client_scalar_coin_hex"] = "03" + "00" * 31
        for index, mutated in enumerate(
            (tau, wrong_plan, wrong_coin, activation_coin)
        ):
            with self.subTest(mutation=index):
                self.assert_rejected_evaluation_input_party_views(mutated)

    def test_evaluation_input_party_views_coins_reproduce_outputs_and_stay_host_only(
        self,
    ) -> None:
        activation_coin = copy.deepcopy(self.evaluation_input_party_views_corpus)
        activation_coin["cases"][0]["vector"][
            "host_only_ideal_function_randomness"
        ]["client_scalar_coin_hex"] = "04" + "00" * 31
        export_coin = copy.deepcopy(self.evaluation_input_party_views_corpus)
        export_coin["cases"][4]["vector"]["host_only_ideal_function_randomness"][
            "seed_output_coin_hex"
        ] = "78" * 32
        leaked = copy.deepcopy(self.evaluation_input_party_views_corpus)
        leaked["cases"][0]["vector"]["role_extensions"]["router"][
            "client_scalar_coin_hex"
        ] = "03" + "00" * 31
        copied_coin = copy.deepcopy(self.evaluation_input_party_views_corpus)
        copied_coin["cases"][0]["vector"]["common_public"][
            "seed_output_coin_hex"
        ] = "77" * 32
        for index, mutated in enumerate(
            (activation_coin, export_coin, leaked, copied_coin)
        ):
            with self.subTest(mutation=index):
                self.assert_rejected_evaluation_input_party_views(mutated)

    def test_evaluation_input_party_views_static_observations_are_exact_copies(
        self,
    ) -> None:
        source = copy.deepcopy(self.evaluation_input_party_views_corpus)
        source["cases"][0]["vector"]["static_deriver_observations"]["deriver_a"][
            "source_case_id"
        ] = "recovery_evaluation_input_party_views_v1"
        stage = copy.deepcopy(self.evaluation_input_party_views_corpus)
        stage["cases"][3]["vector"]["static_deriver_observations"]["deriver_b"][
            "source_stage"
        ] = "recovery_evaluation_accepted"
        peer = copy.deepcopy(self.evaluation_input_party_views_corpus)
        peer["cases"][0]["vector"]["static_deriver_observations"]["deriver_a"][
            "extension"
        ] = copy.deepcopy(
            peer["cases"][0]["vector"]["role_extensions"]["deriver_b"]
        )
        injected = copy.deepcopy(self.evaluation_input_party_views_corpus)
        injected["cases"][0]["vector"]["static_deriver_observations"][
            "deriver_a"
        ]["extension"]["peer_extension"] = copy.deepcopy(
            injected["cases"][0]["vector"]["role_extensions"]["deriver_b"]
        )
        for index, mutated in enumerate((source, stage, peer, injected)):
            with self.subTest(mutation=index):
                self.assert_rejected_evaluation_input_party_views(mutated)

    def test_uniform_abort_auto_detection_and_cli_require_ceremony_companion(self) -> None:
        self.assertEqual(
            verify_vectors.verify_uniform_abort_corpus(
                self.uniform_abort_corpus, self.ceremony_context_corpus
            ),
            5,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                self.uniform_abort_corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
            ),
            5,
        )
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            "uniform-abort verification requires a ceremony-context corpus",
        ):
            verify_vectors.verify_document(self.uniform_abort_corpus)
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main(
                [
                    str(UNIFORM_ABORT_CORPUS_PATH),
                    "--ceremony-context-corpus",
                    str(CEREMONY_CONTEXT_CORPUS_PATH),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 5 independent", output.getvalue())

    def test_uniform_abort_headers_order_and_canonical_bytes_are_strict(self) -> None:
        reordered = {
            "protocol_id": self.uniform_abort_corpus["protocol_id"],
            "schema": self.uniform_abort_corpus["schema"],
            "evidence_scope": self.uniform_abort_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.uniform_abort_corpus["cases"]),
        }
        swapped = copy.deepcopy(self.uniform_abort_corpus)
        swapped["cases"][0], swapped["cases"][2] = (
            swapped["cases"][2],
            swapped["cases"][0],
        )
        for mutated in (reordered, swapped):
            self.assert_rejected_uniform_abort(mutated)

        canonical = (
            json.dumps(self.uniform_abort_corpus, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
        for malformed in (
            canonical[:-1],
            canonical + b"\n",
            canonical.replace(b"\n", b"\r\n"),
            b"\xef\xbb\xbf" + canonical,
        ):
            with patch.object(
                Path, "read_bytes", return_value=malformed
            ), self.assertRaises(verify_vectors.VerificationError):
                verify_vectors.load_corpus(UNIFORM_ABORT_CORPUS_PATH)

    def test_uniform_abort_cross_links_kind_source_and_transcript(self) -> None:
        kind = copy.deepcopy(self.uniform_abort_corpus)
        kind["cases"][0]["envelope"]["request_kind"] = "recovery"
        source = copy.deepcopy(self.uniform_abort_corpus)
        source["cases"][3]["source_ceremony_case_id"] = "ceremony-recovery-v1"
        transcript = copy.deepcopy(self.uniform_abort_corpus)
        transcript["cases"][4]["envelope"][
            "public_transcript_digest_hex"
        ] = "44" * 32
        for mutated in (kind, source, transcript):
            self.assert_rejected_uniform_abort(mutated)

    def test_uniform_abort_has_one_failure_code_and_terminal_state(self) -> None:
        code = copy.deepcopy(self.uniform_abort_corpus)
        code["cases"][1]["envelope"]["public_failure_code"] = "peer_fault"
        terminal = copy.deepcopy(self.uniform_abort_corpus)
        terminal["cases"][2]["envelope"]["terminal"] = "retryable"
        missing = copy.deepcopy(self.uniform_abort_corpus)
        del missing["cases"][0]["envelope"]["terminal"]
        unknown = copy.deepcopy(self.uniform_abort_corpus)
        unknown["cases"][0]["envelope"]["retry_after"] = 1
        for mutated in (code, terminal, missing, unknown):
            self.assert_rejected_uniform_abort(mutated)

    def test_uniform_abort_rejects_private_blame_and_request_context_fields(self) -> None:
        mutations = []
        for field, value in (
            ("request_context_digest_hex", "11" * 32),
            ("authorization_digest_hex", "22" * 32),
            ("deriver_role", "deriver_a"),
            ("peer_frame_hex", "33"),
            ("seed_hex", "44" * 32),
        ):
            mutated = copy.deepcopy(self.uniform_abort_corpus)
            mutated["cases"][0]["envelope"][field] = value
            mutations.append(mutated)
        for mutated in mutations:
            self.assert_rejected_uniform_abort(mutated)

    def test_evaluator_abort_views_auto_detection_and_cli_require_ceremony(self) -> None:
        self.assertEqual(
            verify_vectors.verify_evaluator_abort_view_corpus(
                self.evaluator_abort_view_corpus, self.ceremony_context_corpus
            ),
            4,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                self.evaluator_abort_view_corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
            ),
            4,
        )
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            "evaluator-abort-view verification requires a ceremony-context corpus",
        ):
            verify_vectors.verify_document(self.evaluator_abort_view_corpus)
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main(
                [
                    str(EVALUATOR_ABORT_VIEW_CORPUS_PATH),
                    "--ceremony-context-corpus",
                    str(CEREMONY_CONTEXT_CORPUS_PATH),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 4 independent", output.getvalue())

    def test_evaluator_abort_views_headers_order_and_canonical_bytes_are_strict(self) -> None:
        reordered = {
            "protocol_id": self.evaluator_abort_view_corpus["protocol_id"],
            "schema": self.evaluator_abort_view_corpus["schema"],
            "evidence_scope": self.evaluator_abort_view_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.evaluator_abort_view_corpus["cases"]),
        }
        swapped = copy.deepcopy(self.evaluator_abort_view_corpus)
        swapped["cases"][0], swapped["cases"][1] = (
            swapped["cases"][1],
            swapped["cases"][0],
        )
        for mutated in (reordered, swapped):
            self.assert_rejected_evaluator_abort_views(mutated)

        canonical = (
            json.dumps(self.evaluator_abort_view_corpus, ensure_ascii=False, indent=2)
            + "\n"
        ).encode("utf-8")
        for malformed in (canonical[:-1], canonical + b"\n", canonical.replace(b"\n", b"\r\n")):
            with patch.object(
                Path, "read_bytes", return_value=malformed
            ), self.assertRaises(verify_vectors.VerificationError):
                verify_vectors.load_corpus(EVALUATOR_ABORT_VIEW_CORPUS_PATH)

    def test_evaluator_abort_views_cross_link_burned_ceremony_and_execution_ids(self) -> None:
        request = copy.deepcopy(self.evaluator_abort_view_corpus)
        request["cases"][1]["persistence"]["burned_attempt"][
            "request_context_digest_hex"
        ] = "11" * 32
        authorization = copy.deepcopy(self.evaluator_abort_view_corpus)
        authorization["cases"][2]["persistence"]["burned_attempt"][
            "authorization_digest_hex"
        ] = "22" * 32
        transcript = copy.deepcopy(self.evaluator_abort_view_corpus)
        transcript["cases"][3]["persistence"]["public_abort"][
            "public_transcript_digest_hex"
        ] = "33" * 32
        zero = copy.deepcopy(self.evaluator_abort_view_corpus)
        zero["cases"][0]["persistence"]["burned_attempt"][
            "one_use_execution_id_hex"
        ] = "00" * 32
        duplicate = copy.deepcopy(self.evaluator_abort_view_corpus)
        duplicate["cases"][1]["persistence"]["burned_attempt"][
            "one_use_execution_id_hex"
        ] = duplicate["cases"][0]["persistence"]["burned_attempt"][
            "one_use_execution_id_hex"
        ]
        for mutated in (request, authorization, transcript, zero, duplicate):
            self.assert_rejected_evaluator_abort_views(mutated)

    def test_evaluator_abort_views_enforce_state_class_and_self_loop(self) -> None:
        registration = copy.deepcopy(self.evaluator_abort_view_corpus)
        registration["cases"][0]["persistence"]["pre_state_class"] = "registered"
        recovery = copy.deepcopy(self.evaluator_abort_view_corpus)
        recovery["cases"][1]["persistence"]["pre_state_class"] = "registered"
        transition = copy.deepcopy(self.evaluator_abort_view_corpus)
        transition["cases"][2]["persistence"]["transition"] = "promoted"
        for mutated in (registration, recovery, transition):
            self.assert_rejected_evaluator_abort_views(mutated)

    def test_evaluator_abort_views_are_exact_common_abort_without_private_extensions(self) -> None:
        changed = copy.deepcopy(self.evaluator_abort_view_corpus)
        changed["cases"][0]["party_views"]["deriver_a"]["terminal"] = "retryable"
        private = copy.deepcopy(self.evaluator_abort_view_corpus)
        private["cases"][1]["party_views"]["client"]["seed_hex"] = "44" * 32
        missing = copy.deepcopy(self.evaluator_abort_view_corpus)
        del missing["cases"][2]["party_views"]["diagnostics"]
        blame = copy.deepcopy(self.evaluator_abort_view_corpus)
        blame["cases"][3]["persistence"]["public_abort"]["deriver_blame"] = "deriver_b"
        for mutated in (changed, private, missing, blame):
            self.assert_rejected_evaluator_abort_views(mutated)

    def test_recovery_transition_reproduces_canonical_promotion(self) -> None:
        self.assertEqual(
            verify_vectors.verify_recovery_credential_transition_corpus(
                self.recovery_credential_transition_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
                self.semantic_lifecycle_corpus,
                self.output_party_views_corpus,
                self.activation_delivery_corpus,
                self.activation_recipient_party_views_corpus,
            ),
            1,
        )

    def test_recovery_transition_auto_detection_requires_all_companions(self) -> None:
        self.assertEqual(
            verify_vectors.verify_document(
                self.recovery_credential_transition_corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
                provenance_corpus=self.provenance_corpus,
                semantic_lifecycle_corpus=self.semantic_lifecycle_corpus,
                output_party_views_corpus=self.output_party_views_corpus,
                activation_delivery_corpus=self.activation_delivery_corpus,
                activation_recipient_party_views_corpus=self.activation_recipient_party_views_corpus,
            ),
            1,
        )
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_document(
                self.recovery_credential_transition_corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
                provenance_corpus=self.provenance_corpus,
                semantic_lifecycle_corpus=self.semantic_lifecycle_corpus,
                output_party_views_corpus=self.output_party_views_corpus,
                activation_delivery_corpus=self.activation_delivery_corpus,
            )

    def test_recovery_transition_rejects_state_relation_mutations(self) -> None:
        credential = copy.deepcopy(self.recovery_credential_transition_corpus)
        credential["cases"][0]["promoted"]["next_state"][
            "active_credential_binding_digest_hex"
        ] = "44" * 32
        root = copy.deepcopy(self.recovery_credential_transition_corpus)
        root["cases"][0]["promoted"]["next_state"]["deriver_a_root_record_hex"] = (
            "45" * 32
        )
        version = copy.deepcopy(self.recovery_credential_transition_corpus)
        version["cases"][0]["promoted"]["next_state"]["active_state_version"] = 9
        for mutated in (credential, root, version):
            self.assert_rejected_recovery_credential_transition(mutated)

    def test_recovery_transition_rejects_tombstone_mutations(self) -> None:
        credential = copy.deepcopy(self.recovery_credential_transition_corpus)
        credential["cases"][0]["promoted"]["tombstone"][
            "credential_binding_digest_hex"
        ] = "43" * 32
        version = copy.deepcopy(self.recovery_credential_transition_corpus)
        version["cases"][0]["promoted"]["tombstone"]["retired_state_version"] = 10
        digest = copy.deepcopy(self.recovery_credential_transition_corpus)
        digest["cases"][0]["promoted"]["tombstone"]["tombstone_digest_hex"] = (
            "00" * 32
        )
        for mutated in (credential, version, digest):
            self.assert_rejected_recovery_credential_transition(mutated)

    def test_recovery_transition_rejects_receipt_and_signature_mutations(self) -> None:
        receipt = copy.deepcopy(self.recovery_credential_transition_corpus)
        receipt["cases"][0]["promoted"]["promotion_receipt_encoding_hex"] = (
            receipt["cases"][0]["promoted"]["promotion_receipt_encoding_hex"][:-2]
            + "00"
        )
        digest = copy.deepcopy(self.recovery_credential_transition_corpus)
        digest["cases"][0]["promoted"]["promotion_receipt_digest_hex"] = "00" * 32
        signature = copy.deepcopy(self.recovery_credential_transition_corpus)
        signature["cases"][0]["promoted"]["promotion_receipt_signature_hex"] = (
            "00" * 64
        )
        for mutated in (receipt, digest, signature):
            self.assert_rejected_recovery_credential_transition(mutated)

    def test_recovery_transition_rejects_coherent_authority_substitution(self) -> None:
        mutated = copy.deepcopy(self.recovery_credential_transition_corpus)
        promoted = mutated["cases"][0]["promoted"]
        encoding = bytes.fromhex(promoted["promotion_receipt_encoding_hex"])
        fields = list(verify_vectors._parse_lp32_fields(encoding, 20, "receipt"))
        attacker_public_key = verify_vectors._derive_ed25519_public_key_from_seed(
            bytes((0x6B,)) * 32
        )
        fields[2] = hashlib.sha256(
            verify_vectors._lp32_join(
                (verify_vectors.STORE_AUTHORITY_KEY_DIGEST_DOMAIN_V1, attacker_public_key)
            )
        ).digest()
        attacker_encoding = verify_vectors._lp32_join(tuple(fields))
        _, attacker_signature = _sign_ed25519_fixture(
            bytes((0x6B,)) * 32, attacker_encoding
        )
        promoted["promotion_receipt_encoding_hex"] = attacker_encoding.hex()
        promoted["promotion_receipt_digest_hex"] = hashlib.sha256(
            verify_vectors._lp32_join(
                (
                    verify_vectors.RECOVERY_PROMOTION_RECEIPT_DIGEST_DOMAIN_V1,
                    attacker_encoding,
                )
            )
        ).hexdigest()
        promoted["promotion_receipt_signature_hex"] = attacker_signature.hex()
        self.assert_rejected_recovery_credential_transition(mutated)

    def test_recovery_transition_rejects_cross_links_and_forbidden_fields(self) -> None:
        source = copy.deepcopy(self.recovery_credential_transition_corpus)
        source["cases"][0]["source_references"]["provenance_case_id"] = (
            "refresh_provenance_outer_v1"
        )
        activated = copy.deepcopy(self.recovery_credential_transition_corpus)
        activated["cases"][0]["worker_activated"]["package_set_digest_hex"] = "00" * 32
        forbidden = copy.deepcopy(self.recovery_credential_transition_corpus)
        forbidden["cases"][0]["promoted"]["security_profile"] = "p2"
        for mutated in (source, activated, forbidden):
            self.assert_rejected_recovery_credential_transition(mutated)

    def test_export_evaluator_authorization_reproduces_canonical_pair(self) -> None:
        self.assertEqual(
            verify_vectors.verify_export_evaluator_authorization_corpus(
                self.export_evaluator_authorization_corpus
            ),
            1,
        )
        self.assertEqual(
            verify_vectors.verify_document(self.export_evaluator_authorization_corpus),
            1,
        )

    def test_export_evaluator_authorization_rejects_role_and_key_swap(self) -> None:
        role = copy.deepcopy(self.export_evaluator_authorization_corpus)
        role["cases"][0]["acceptances"]["deriver_a"]["role"] = "deriver_b"
        key = copy.deepcopy(self.export_evaluator_authorization_corpus)
        key["cases"][0]["authorities"]["deriver_a"]["verifying_key_hex"] = key[
            "cases"
        ][0]["authorities"]["deriver_b"]["verifying_key_hex"]
        pair = copy.deepcopy(self.export_evaluator_authorization_corpus)
        encoded = bytes.fromhex(pair["cases"][0]["accepted_pair"]["encoding_hex"])
        fields = list(verify_vectors._parse_lp32_fields(encoded, 3, "pair"))
        fields[1], fields[2] = fields[2], fields[1]
        pair["cases"][0]["accepted_pair"]["encoding_hex"] = verify_vectors._lp32_join(
            tuple(fields)
        ).hex()
        for mutated in (role, key, pair):
            self.assert_rejected_export_evaluator_authorization(mutated)

    def test_export_evaluator_authorization_rejects_signature_mutation(self) -> None:
        for role in ("deriver_a", "deriver_b"):
            mutated = copy.deepcopy(self.export_evaluator_authorization_corpus)
            mutated["cases"][0]["acceptances"][role]["signature_hex"] = "00" * 64
            self.assert_rejected_export_evaluator_authorization(mutated)

    def test_export_evaluator_authorization_rejects_request_and_execution_splice(self) -> None:
        request = copy.deepcopy(self.export_evaluator_authorization_corpus)
        request["cases"][0]["common"]["replay_nonce_hex"] = "81" * 32
        execution = copy.deepcopy(self.export_evaluator_authorization_corpus)
        execution["cases"][0]["common"]["one_use_execution_id_hex"] = "82" * 32
        authorization = copy.deepcopy(self.export_evaluator_authorization_corpus)
        authorization["cases"][0]["common"]["authorization_digest_hex"] = "83" * 32
        for mutated in (request, execution, authorization):
            self.assert_rejected_export_evaluator_authorization(mutated)

    def test_export_evaluator_authorization_rejects_expiry_and_state_splice(self) -> None:
        expired = copy.deepcopy(self.export_evaluator_authorization_corpus)
        expired["cases"][0]["acceptances"]["deriver_a"]["checked_at_unix_ms"] = (
            expired["cases"][0]["common"]["request_expiry_unix_ms"] + 1
        )
        state = copy.deepcopy(self.export_evaluator_authorization_corpus)
        state["cases"][0]["common"]["active_state_version"] += 1
        provenance = copy.deepcopy(self.export_evaluator_authorization_corpus)
        provenance["cases"][0]["common"]["provenance_pair_digest_hex"] = "84" * 32
        for mutated in (expired, state, provenance):
            self.assert_rejected_export_evaluator_authorization(mutated)

    def test_export_evaluator_authorization_rejects_coherent_authority_substitution(self) -> None:
        mutated = copy.deepcopy(self.export_evaluator_authorization_corpus)
        role = "deriver_a"
        authority = mutated["cases"][0]["authorities"][role]
        acceptance = mutated["cases"][0]["acceptances"][role]
        attacker_seed = bytes((0x7A,)) * 32
        attacker_key = verify_vectors._derive_ed25519_public_key_from_seed(attacker_seed)
        authority["verifying_key_hex"] = attacker_key.hex()
        key_digest = hashlib.sha256(
            verify_vectors._lp32_join(
                (
                    verify_vectors.EXPORT_AUTHORIZATION_ACCEPTANCE_AUTHORITY_KEY_DIGEST_DOMAIN_V1,
                    b"\x01",
                    authority["key_epoch"].to_bytes(8, "big"),
                    attacker_key,
                )
            )
        ).digest()
        authority["key_digest_hex"] = key_digest.hex()
        signing_bytes = bytes.fromhex(acceptance["signing_bytes_hex"])
        fields = list(verify_vectors._parse_lp32_fields(signing_bytes, 24, "acceptance"))
        fields[6] = key_digest
        attacker_signing_bytes = verify_vectors._lp32_join(tuple(fields))
        _, attacker_signature = _sign_ed25519_fixture(attacker_seed, attacker_signing_bytes)
        acceptance["signing_bytes_hex"] = attacker_signing_bytes.hex()
        acceptance["signature_hex"] = attacker_signature.hex()
        acceptance["signed_artifact_digest_hex"] = hashlib.sha256(
            verify_vectors._lp32_join(
                (
                    verify_vectors.EXPORT_AUTHORIZATION_ACCEPTANCE_DIGEST_DOMAIN_V1,
                    attacker_signing_bytes,
                    attacker_signature,
                )
            )
        ).hexdigest()
        self.assert_rejected_export_evaluator_authorization(mutated)

    def test_export_evaluator_authorization_rejects_receipt_and_forbidden_drift(self) -> None:
        evidence = copy.deepcopy(self.export_evaluator_authorization_corpus)
        evidence["cases"][0]["evaluation"][
            "released_evaluation_evidence_digest_hex"
        ] = "85" * 32
        committed_digest = copy.deepcopy(self.export_evaluator_authorization_corpus)
        committed_digest["cases"][0]["evaluation"][
            "output_committed_receipt_digest_hex"
        ] = "11" * 32
        released_digest = copy.deepcopy(self.export_evaluator_authorization_corpus)
        released_digest["cases"][0]["evaluation"]["released_receipt_digest_hex"] = (
            "22" * 32
        )
        released_encoding = copy.deepcopy(self.export_evaluator_authorization_corpus)
        encoded = bytearray.fromhex(
            released_encoding["cases"][0]["evaluation"][
                "released_receipt_encoding_hex"
            ]
        )
        encoded[-1] ^= 1
        released_encoding["cases"][0]["evaluation"][
            "released_receipt_encoding_hex"
        ] = encoded.hex()
        state = copy.deepcopy(self.export_evaluator_authorization_corpus)
        state["cases"][0]["evaluation"]["registered_state_retained"] = False
        forbidden = copy.deepcopy(self.export_evaluator_authorization_corpus)
        forbidden["cases"][0]["evaluation"]["joined_seed_hex"] = "86" * 32
        for mutated in (
            evidence,
            committed_digest,
            released_digest,
            released_encoding,
            state,
            forbidden,
        ):
            self.assert_rejected_export_evaluator_authorization(mutated)

    def test_registration_evaluator_admission_reproduces_canonical_case(self) -> None:
        self.assertEqual(
            verify_vectors.verify_registration_evaluator_admission_corpus(
                self.registration_evaluator_admission_corpus
            ),
            1,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                self.registration_evaluator_admission_corpus
            ),
            1,
        )

    def test_registration_evaluator_admission_rejects_schema_and_order_drift(self) -> None:
        schema = copy.deepcopy(self.registration_evaluator_admission_corpus)
        schema["schema"] = "wrong"
        order = copy.deepcopy(self.registration_evaluator_admission_corpus)
        case = order["cases"][0]
        order["cases"][0] = {
            "request_kind": case["request_kind"],
            "case_id": case["case_id"],
            **{key: value for key, value in case.items() if key not in {"case_id", "request_kind"}},
        }
        for mutated in (schema, order):
            self.assert_rejected_registration_evaluator_admission(mutated)

    def test_registration_evaluator_admission_rejects_request_scope_and_authorization_splice(self) -> None:
        request = copy.deepcopy(self.registration_evaluator_admission_corpus)
        request["cases"][0]["admission"]["replay_nonce_hex"] = "a1" * 32
        scope = copy.deepcopy(self.registration_evaluator_admission_corpus)
        encoded_scope = bytearray.fromhex(
            scope["cases"][0]["admission"][
                "unregistered_public_identity_scope_encoding_hex"
            ]
        )
        encoded_scope[-1] ^= 1
        scope["cases"][0]["admission"][
            "unregistered_public_identity_scope_encoding_hex"
        ] = encoded_scope.hex()
        authorization = copy.deepcopy(self.registration_evaluator_admission_corpus)
        authorization["cases"][0]["admission"]["authorization_digest_hex"] = (
            "a2" * 32
        )
        expired = copy.deepcopy(self.registration_evaluator_admission_corpus)
        expired["cases"][0]["admission"]["checked_at_unix_ms"] = (
            expired["cases"][0]["admission"]["request_expiry_unix_ms"] + 1
        )
        for mutated in (request, scope, authorization, expired):
            self.assert_rejected_registration_evaluator_admission(mutated)

    def test_registration_evaluator_admission_rejects_intent_and_provenance_splice(self) -> None:
        intent = copy.deepcopy(self.registration_evaluator_admission_corpus)
        intent["cases"][0]["admission"]["registration_intent_digest_hex"] = (
            "b1" * 32
        )
        provenance = copy.deepcopy(self.registration_evaluator_admission_corpus)
        provenance["cases"][0]["admission"]["provenance_pair_digest_hex"] = (
            "b2" * 32
        )
        statement = copy.deepcopy(self.registration_evaluator_admission_corpus)
        statement["cases"][0]["admission"]["deriver_a_statement_digest_hex"] = (
            "b3" * 32
        )
        input_selection = copy.deepcopy(self.registration_evaluator_admission_corpus)
        input_selection["cases"][0]["admission"][
            "provenance_input_selection_artifact_digest_hex"
        ] = "b4" * 32
        for mutated in (intent, provenance, statement, input_selection):
            self.assert_rejected_registration_evaluator_admission(mutated)

    def test_registration_evaluator_admission_rejects_selection_epoch_and_execution_splice(self) -> None:
        selection = copy.deepcopy(self.registration_evaluator_admission_corpus)
        selection["cases"][0]["admission"]["selection_attempt_id_hex"] = "c1" * 32
        evidence = copy.deepcopy(self.registration_evaluator_admission_corpus)
        evidence["cases"][0]["admission"][
            "selected_mechanism_acceptance_evidence_digest_hex"
        ] = "c2" * 32
        epoch = copy.deepcopy(self.registration_evaluator_admission_corpus)
        epoch["cases"][0]["admission"]["activation_epoch"] += 1
        execution = copy.deepcopy(self.registration_evaluator_admission_corpus)
        execution["cases"][0]["admission"]["one_use_execution_id_hex"] = (
            "c3" * 32
        )
        for mutated in (selection, evidence, epoch, execution):
            self.assert_rejected_registration_evaluator_admission(mutated)

    def test_registration_evaluator_admission_rejects_output_and_receipt_splice(self) -> None:
        public_key = copy.deepcopy(self.registration_evaluator_admission_corpus)
        public_key["cases"][0]["evaluation"]["registered_public_key_hex"] = (
            "d1" * 32
        )
        receipt = copy.deepcopy(self.registration_evaluator_admission_corpus)
        receipt_bytes = bytearray.fromhex(
            receipt["cases"][0]["evaluation"][
                "output_committed_receipt_encoding_hex"
            ]
        )
        receipt_bytes[-1] ^= 1
        receipt["cases"][0]["evaluation"][
            "output_committed_receipt_encoding_hex"
        ] = receipt_bytes.hex()
        receipt_digest = copy.deepcopy(self.registration_evaluator_admission_corpus)
        receipt_digest["cases"][0]["evaluation"][
            "output_committed_receipt_digest_hex"
        ] = "d2" * 32
        candidate = copy.deepcopy(self.registration_evaluator_admission_corpus)
        candidate["cases"][0]["evaluation"]["candidate_digest_hex"] = "d3" * 32
        for mutated in (public_key, receipt, receipt_digest, candidate):
            self.assert_rejected_registration_evaluator_admission(mutated)

    def test_registration_evaluator_admission_rejects_retry_resampling_and_forbidden_fields(self) -> None:
        retry = copy.deepcopy(self.registration_evaluator_admission_corpus)
        retry["cases"][0]["retry"]["retry_may_resample_selection"] = True
        terminal = copy.deepcopy(self.registration_evaluator_admission_corpus)
        terminal["cases"][0]["retry"][
            "evaluator_abort_retains_terminal_selection"
        ] = False
        forbidden = copy.deepcopy(self.registration_evaluator_admission_corpus)
        forbidden["cases"][0]["evaluation"]["security_profile"] = "p2"
        claims = copy.deepcopy(self.registration_evaluator_admission_corpus)
        claims["cases"][0]["claim_boundary"]["excluded_claims"].pop()
        for mutated in (retry, terminal, forbidden, claims):
            self.assert_rejected_registration_evaluator_admission(mutated)

    def test_recovery_evaluator_admission_reproduces_canonical_case(self) -> None:
        self.assertEqual(
            verify_vectors.verify_recovery_evaluator_admission_corpus(
                self.recovery_evaluator_admission_corpus
            ),
            1,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                self.recovery_evaluator_admission_corpus
            ),
            1,
        )

    def test_recovery_evaluator_admission_rejects_schema_and_order_drift(self) -> None:
        schema = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        schema["schema"] = "wrong"
        order = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        case = order["cases"][0]
        order["cases"][0] = {
            "request_kind": case["request_kind"],
            "case_id": case["case_id"],
            **{
                key: value
                for key, value in case.items()
                if key not in {"case_id", "request_kind"}
            },
        }
        for mutated in (schema, order):
            self.assert_rejected_recovery_evaluator_admission(mutated)

    def test_recovery_evaluator_admission_rejects_request_scope_authorization_and_expiry_splice(self) -> None:
        request = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        request["cases"][0]["admission"]["request_id"] = "request-recovery-spliced"
        scope = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        encoded_scope = bytearray.fromhex(
            scope["cases"][0]["admission"]["durable_identity_scope_encoding_hex"]
        )
        encoded_scope[-1] ^= 1
        scope["cases"][0]["admission"][
            "durable_identity_scope_encoding_hex"
        ] = encoded_scope.hex()
        authorization = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        authorization["cases"][0]["admission"]["authorization_digest_hex"] = (
            "a2" * 32
        )
        expired = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        expired["cases"][0]["admission"]["checked_at_unix_ms"] = (
            expired["cases"][0]["admission"]["request_expiry_unix_ms"] + 1
        )
        for mutated in (request, scope, authorization, expired):
            self.assert_rejected_recovery_evaluator_admission(mutated)

    def test_recovery_evaluator_admission_rejects_store_resolution_state_and_authority_splice(self) -> None:
        authority = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        authority["cases"][0]["authenticated_store_resolution"][
            "authority_key_digest_hex"
        ] = "b1" * 32
        version = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        version["cases"][0]["authenticated_store_resolution"][
            "active_state_version"
        ] += 1
        registered_key = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        registered_key["cases"][0]["authenticated_store_resolution"][
            "registered_public_key_hex"
        ] = "b2" * 32
        signing_bytes = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        encoded_store = bytearray.fromhex(
            signing_bytes["cases"][0]["authenticated_store_resolution"][
                "signing_bytes_hex"
            ]
        )
        encoded_store[-1] ^= 1
        signing_bytes["cases"][0]["authenticated_store_resolution"][
            "signing_bytes_hex"
        ] = encoded_store.hex()
        for mutated in (authority, version, registered_key, signing_bytes):
            self.assert_rejected_recovery_evaluator_admission(mutated)

    def test_recovery_evaluator_admission_rejects_continuity_provenance_and_evidence_splice(self) -> None:
        active = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        active["cases"][0]["admission"][
            "active_credential_binding_digest_hex"
        ] = "c1" * 32
        replacement = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        replacement["cases"][0]["admission"][
            "replacement_credential_binding_digest_hex"
        ] = "c2" * 32
        same_root = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        same_root["cases"][0]["admission"][
            "provenance_same_root_artifact_digest_hex"
        ] = "c3" * 32
        selected_evidence = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        selected_evidence["cases"][0]["admission"][
            "selected_mechanism_acceptance_evidence_digest_hex"
        ] = "c4" * 32
        statement = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        statement["cases"][0]["admission"][
            "deriver_a_statement_digest_hex"
        ] = "c5" * 32
        for mutated in (
            active,
            replacement,
            same_root,
            selected_evidence,
            statement,
        ):
            self.assert_rejected_recovery_evaluator_admission(mutated)

    def test_recovery_evaluator_admission_rejects_epoch_execution_output_and_receipt_splice(self) -> None:
        epoch = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        epoch["cases"][0]["admission"]["next_activation_epoch"] += 1
        execution = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        execution["cases"][0]["admission"]["one_use_execution_id_hex"] = (
            "d1" * 32
        )
        output = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        output["cases"][0]["evaluation"]["package_set_digest_hex"] = "d2" * 32
        receipt = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        receipt_bytes = bytearray.fromhex(
            receipt["cases"][0]["evaluation"][
                "output_committed_receipt_encoding_hex"
            ]
        )
        receipt_bytes[-1] ^= 1
        receipt["cases"][0]["evaluation"][
            "output_committed_receipt_encoding_hex"
        ] = receipt_bytes.hex()
        receipt_digest = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        receipt_digest["cases"][0]["evaluation"][
            "output_committed_receipt_digest_hex"
        ] = "d3" * 32
        for mutated in (epoch, execution, output, receipt, receipt_digest):
            self.assert_rejected_recovery_evaluator_admission(mutated)

    def test_recovery_evaluator_admission_rejects_retry_claim_and_forbidden_field_drift(self) -> None:
        retry = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        retry["cases"][0]["retry"]["retry_requires_fresh_execution"] = False
        suspension = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        suspension["cases"][0]["retry"][
            "evaluator_abort_retains_credential_suspension"
        ] = False
        claims = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        claims["cases"][0]["claim_boundary"]["excluded_claims"].pop()
        forbidden = copy.deepcopy(self.recovery_evaluator_admission_corpus)
        forbidden["cases"][0]["evaluation"]["security_profile"] = "p2"
        for mutated in (retry, suspension, claims, forbidden):
            self.assert_rejected_recovery_evaluator_admission(mutated)

    def test_refresh_evaluator_admission_reproduces_canonical_case(self) -> None:
        self.assertEqual(
            verify_vectors.verify_refresh_evaluator_admission_corpus(
                self.refresh_evaluator_admission_corpus
            ),
            1,
        )
        self.assertEqual(
            verify_vectors.verify_document(self.refresh_evaluator_admission_corpus),
            1,
        )

    def test_refresh_evaluator_admission_rejects_schema_and_order_drift(self) -> None:
        schema = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        schema["schema"] = "wrong"
        case_order = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        case = case_order["cases"][0]
        case_order["cases"][0] = {
            "request_kind": case["request_kind"],
            "case_id": case["case_id"],
            **{
                key: value
                for key, value in case.items()
                if key not in {"case_id", "request_kind"}
            },
        }
        role_order = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        next_a = role_order["cases"][0]["admission"]["next_deriver_a"]
        role_order["cases"][0]["admission"]["next_deriver_a"] = {
            "role_root_record_digest_hex": next_a["role_root_record_digest_hex"],
            "role": next_a["role"],
            **{
                key: value
                for key, value in next_a.items()
                if key not in {"role", "role_root_record_digest_hex"}
            },
        }
        for mutated in (schema, case_order, role_order):
            self.assert_rejected_refresh_evaluator_admission(mutated)

    def test_refresh_evaluator_admission_rejects_request_scope_authorization_and_expiry_splice(self) -> None:
        request = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        request["cases"][0]["admission"]["request_id"] = "request-refresh-spliced"
        scope = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        encoded_scope = bytearray.fromhex(
            scope["cases"][0]["admission"]["durable_identity_scope_encoding_hex"]
        )
        encoded_scope[-1] ^= 1
        scope["cases"][0]["admission"][
            "durable_identity_scope_encoding_hex"
        ] = encoded_scope.hex()
        authorization = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        authorization["cases"][0]["admission"]["authorization_digest_hex"] = (
            "a2" * 32
        )
        expired = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        expired["cases"][0]["admission"]["checked_at_unix_ms"] = (
            expired["cases"][0]["admission"]["request_expiry_unix_ms"] + 1
        )
        for mutated in (request, scope, authorization, expired):
            self.assert_rejected_refresh_evaluator_admission(mutated)

    def test_refresh_evaluator_admission_rejects_store_resolution_state_and_authority_splice(self) -> None:
        authority = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        authority["cases"][0]["authenticated_store_resolution"][
            "authority_key_digest_hex"
        ] = "b1" * 32
        signature = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        signature["cases"][0]["authenticated_store_resolution"][
            "authority_signature_hex"
        ] = "b2" * 64
        version = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        version["cases"][0]["authenticated_store_resolution"][
            "active_state_version"
        ] += 1
        registered_key = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        registered_key["cases"][0]["authenticated_store_resolution"][
            "registered_public_key_hex"
        ] = "b3" * 32
        signing_bytes = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        encoded_store = bytearray.fromhex(
            signing_bytes["cases"][0]["authenticated_store_resolution"][
                "signing_bytes_hex"
            ]
        )
        encoded_store[-1] ^= 1
        signing_bytes["cases"][0]["authenticated_store_resolution"][
            "signing_bytes_hex"
        ] = encoded_store.hex()
        for mutated in (authority, signature, version, registered_key, signing_bytes):
            self.assert_rejected_refresh_evaluator_admission(mutated)

    def test_refresh_evaluator_admission_rejects_role_transition_provenance_and_evidence_splice(self) -> None:
        next_root = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        next_root["cases"][0]["admission"]["next_deriver_a"][
            "role_root_record_digest_hex"
        ] = "c1" * 32
        next_epoch = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        next_epoch["cases"][0]["admission"]["next_deriver_b"][
            "input_state_epoch"
        ] = next_epoch["cases"][0]["admission"][
            "current_deriver_b_input_state_epoch"
        ]
        continuity = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        continuity["cases"][0]["admission"][
            "provenance_continuity_evidence_artifact_digest_hex"
        ] = "c2" * 32
        selected = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        selected["cases"][0]["admission"][
            "selected_mechanism_acceptance_evidence_digest_hex"
        ] = "c3" * 32
        statement = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        statement["cases"][0]["admission"]["deriver_a_statement_digest_hex"] = (
            "c4" * 32
        )
        for mutated in (next_root, next_epoch, continuity, selected, statement):
            self.assert_rejected_refresh_evaluator_admission(mutated)

    def test_refresh_evaluator_admission_rejects_epoch_execution_output_and_receipt_splice(self) -> None:
        activation_epoch = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        activation_epoch["cases"][0]["admission"]["next_activation_epoch"] += 1
        current_role_epoch = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        current_role_epoch["cases"][0]["admission"][
            "current_deriver_a_input_state_epoch"
        ] += 1
        execution = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        execution["cases"][0]["admission"]["one_use_execution_id_hex"] = (
            "d1" * 32
        )
        output = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        output["cases"][0]["evaluation"]["package_set_digest_hex"] = "d2" * 32
        receipt = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        receipt_bytes = bytearray.fromhex(
            receipt["cases"][0]["evaluation"][
                "output_committed_receipt_encoding_hex"
            ]
        )
        receipt_bytes[-1] ^= 1
        receipt["cases"][0]["evaluation"][
            "output_committed_receipt_encoding_hex"
        ] = receipt_bytes.hex()
        receipt_digest = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        receipt_digest["cases"][0]["evaluation"][
            "output_committed_receipt_digest_hex"
        ] = "d3" * 32
        for mutated in (
            activation_epoch,
            current_role_epoch,
            execution,
            output,
            receipt,
            receipt_digest,
        ):
            self.assert_rejected_refresh_evaluator_admission(mutated)

    def test_refresh_evaluator_admission_rejects_retry_claim_nonclaim_and_forbidden_drift(self) -> None:
        retry = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        retry["cases"][0]["retry"]["retry_requires_fresh_execution"] = False
        terminal = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        terminal["cases"][0]["evaluation"]["terminal_admission_retained"] = False
        proposal = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        proposal["cases"][0]["evaluation"][
            "proposed_next_role_states_retained"
        ] = False
        claims = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        claims["cases"][0]["claim_boundary"]["excluded_claims"].pop()
        policy = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        policy["cases"][0]["claim_boundary"]["forbidden_fields"].pop()
        forbidden = copy.deepcopy(self.refresh_evaluator_admission_corpus)
        forbidden["cases"][0]["evaluation"]["private_delta_hex"] = "00" * 32
        for mutated in (retry, terminal, proposal, claims, policy, forbidden):
            self.assert_rejected_refresh_evaluator_admission(mutated)

    def test_provenance_corpus_auto_detection_reproduces_all_four_cases(self) -> None:
        self.assertEqual(
            verify_vectors.verify_provenance_corpus(
                self.provenance_corpus, self.ceremony_context_corpus
            ),
            4,
        )
        self.assertEqual(
            verify_vectors.verify_provenance_ceremony_links(
                self.ceremony_context_corpus, self.provenance_corpus
            ),
            4,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                self.provenance_corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
            ),
            4,
        )
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            "requires a ceremony-context corpus",
        ):
            verify_vectors.verify_document(self.provenance_corpus)
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            "applies only to provenance or semantic-lifecycle vectors",
        ):
            verify_vectors.verify_document(
                self.corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
            )
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = verify_vectors.main(
                [
                    str(PROVENANCE_CORPUS_PATH),
                    "--ceremony-context-corpus",
                    str(CEREMONY_CONTEXT_CORPUS_PATH),
                ]
            )
        self.assertEqual(exit_code, 0)
        self.assertIn("verified 4 independent", output.getvalue())

    def test_provenance_ceremony_links_reject_coherent_outer_digest_splicing(
        self,
    ) -> None:
        mutated = copy.deepcopy(self.provenance_corpus)
        _rewrite_provenance_request_context_digest(mutated, 0, bytes((0xAA,)) * 32)
        self.assertEqual(verify_vectors._verify_provenance_outer_corpus(mutated), 4)
        with self.assertRaisesRegex(
            verify_vectors.VerificationError,
            "do not match the independently reconstructed DAG",
        ):
            verify_vectors.verify_provenance_ceremony_links(
                self.ceremony_context_corpus, mutated
            )

    def test_provenance_closed_shapes_headers_order_and_activation_absence(self) -> None:
        mutations: list[dict[str, Any]] = []
        unknown = copy.deepcopy(self.provenance_corpus)
        unknown["cases"][0]["vector"]["deriver_a"]["proof_hex"] = "00"
        mutations.append(unknown)
        missing = copy.deepcopy(self.provenance_corpus)
        del missing["cases"][0]["vector"]["pair_encoding_hex"]
        mutations.append(missing)
        activation = copy.deepcopy(self.provenance_corpus)
        activation["cases"][0]["request_kind"] = "activation"
        mutations.append(activation)
        ceremony_kind = copy.deepcopy(self.provenance_corpus)
        role = ceremony_kind["cases"][0]["vector"]["deriver_a"]
        role["ceremony_binding_encoding_hex"] = _replace_lp32_field(
            role["ceremony_binding_encoding_hex"], 1, bytes((5,))
        )
        role["statement_encoding_hex"] = _replace_lp32_field(
            role["statement_encoding_hex"],
            9,
            bytes.fromhex(role["ceremony_binding_encoding_hex"]),
        )
        mutations.append(ceremony_kind)
        reordered = {
            "protocol_id": self.provenance_corpus["protocol_id"],
            "schema": self.provenance_corpus["schema"],
            "evidence_scope": self.provenance_corpus["evidence_scope"],
            "artifact_wrapper_goldens": copy.deepcopy(
                self.provenance_corpus["artifact_wrapper_goldens"]
            ),
            "cases": copy.deepcopy(self.provenance_corpus["cases"]),
        }
        mutations.append(reordered)
        for mutated in mutations:
            with self.subTest(mutation=len(mutations)):
                self.assert_rejected_provenance(mutated)

    def test_provenance_rejects_artifact_statement_and_pair_digest_mutations(self) -> None:
        artifact = copy.deepcopy(self.provenance_corpus)
        artifact["artifact_wrapper_goldens"][0]["digest_sha256_hex"] = "00" * 32
        self.assert_rejected_provenance(artifact)

        statement = copy.deepcopy(self.provenance_corpus)
        statement["cases"][0]["vector"]["deriver_a"][
            "statement_digest_sha256_hex"
        ] = "00" * 32
        self.assert_rejected_provenance(statement)

        pair = copy.deepcopy(self.provenance_corpus)
        pair["cases"][0]["vector"]["pair_digest_sha256_hex"] = "00" * 32
        self.assert_rejected_provenance(pair)

    def test_provenance_rejects_role_family_and_cross_branch_mutations(self) -> None:
        role = copy.deepcopy(self.provenance_corpus)
        role["cases"][0]["vector"]["deriver_a"]["role_tag"] = 2
        self.assert_rejected_provenance(role)

        family = copy.deepcopy(self.provenance_corpus)
        role_vector = family["cases"][0]["vector"]["deriver_a"]
        role_vector["statement_encoding_hex"] = _replace_lp32_field(
            role_vector["statement_encoding_hex"], 4, bytes((2,))
        )
        self.assert_rejected_provenance(family)

        cross_branch = copy.deepcopy(self.provenance_corpus)
        cross_branch["cases"][0]["request_kind"] = "recovery"
        self.assert_rejected_provenance(cross_branch)

    def test_provenance_rejects_envelope_order_and_nested_encoding_mutations(self) -> None:
        envelope = copy.deepcopy(self.provenance_corpus)
        vector = envelope["cases"][0]["vector"]
        (
            vector["client_envelope_a_artifact_digest_hex"],
            vector["client_envelope_b_artifact_digest_hex"],
        ) = (
            vector["client_envelope_b_artifact_digest_hex"],
            vector["client_envelope_a_artifact_digest_hex"],
        )
        self.assert_rejected_provenance(envelope)

        nested = copy.deepcopy(self.provenance_corpus)
        nested["cases"][2]["vector"]["deriver_a"]["snapshot_encodings_hex"][1] = (
            "00"
        )
        self.assert_rejected_provenance(nested)

    def test_provenance_registered_public_key_validation_rejects_bad_points(self) -> None:
        for encoded in (bytes(32), bytes((1,)) + bytes(31), bytes((0xFF,)) * 32):
            with self.subTest(encoded=encoded.hex()):
                with self.assertRaises(verify_vectors.VerificationError):
                    verify_vectors._verify_registered_public_key(encoded, "$point")

    def test_provenance_schema_rejects_differential_seed_mode(self) -> None:
        with self.assertRaisesRegex(
            verify_vectors.VerificationError, "applies only to the arithmetic"
        ):
            verify_vectors.verify_document(
                self.provenance_corpus, differential_seed=DIFFERENTIAL_SEED
            )

    def assert_rejected_kdf(self, corpus: dict[str, Any], pattern: str) -> None:
        with self.assertRaisesRegex(verify_vectors.VerificationError, pattern):
            verify_vectors.verify_kdf_corpus(corpus)

    def test_export_delivery_accepts_canonical_corpus_and_dispatch(self) -> None:
        self.assertEqual(
            verify_vectors.verify_export_delivery_corpus(
                self.export_delivery_corpus
            ),
            1,
        )
        self.assertEqual(
            verify_vectors.verify_document(self.export_delivery_corpus),
            1,
        )

    def test_export_delivery_rejects_output_commitment_mutations(self) -> None:
        encoding = copy.deepcopy(self.export_delivery_corpus)
        output_committed = encoding["cases"][0]["output_committed"]
        output_committed["output_committed_receipt_encoding_hex"] = (
            output_committed["output_committed_receipt_encoding_hex"][:-2] + "00"
        )
        self.assert_rejected_export_delivery(encoding)

        digest = copy.deepcopy(self.export_delivery_corpus)
        digest["cases"][0]["output_committed"][
            "output_committed_receipt_digest_hex"
        ] = "00" * 32
        self.assert_rejected_export_delivery(digest)

    def test_export_delivery_rejects_authorization_and_version_mutations(self) -> None:
        output_state = copy.deepcopy(self.export_delivery_corpus)
        output_state["cases"][0]["output_committed"]["authorization_state"] = (
            "consumed"
        )
        self.assert_rejected_export_delivery(output_state)

        released_state = copy.deepcopy(self.export_delivery_corpus)
        released_state["cases"][0]["released"]["authorization_state"] = (
            "unconsumed"
        )
        self.assert_rejected_export_delivery(released_state)

        version = copy.deepcopy(self.export_delivery_corpus)
        version["cases"][0]["released"]["active_state_version"] += 1
        self.assert_rejected_export_delivery(version)

    def test_export_delivery_rejects_release_binding_mutations(self) -> None:
        for field in (
            "output_committed_receipt_digest_hex",
            "client_delivery_evidence_digest_hex",
            "consumed_authorization_evidence_digest_hex",
            "released_receipt_digest_hex",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.export_delivery_corpus)
                mutated["cases"][0]["released"][field] = "00" * 32
                self.assert_rejected_export_delivery(mutated)

    def test_export_delivery_rejects_redelivery_and_schema_mutations(self) -> None:
        for field in (
            "before_released_receipt_digest_hex",
            "after_released_receipt_digest_hex",
            "client_seed_hex",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.export_delivery_corpus)
                mutated["cases"][0]["redelivered"][field] = "00" * 32
                self.assert_rejected_export_delivery(mutated)

        work = copy.deepcopy(self.export_delivery_corpus)
        work["cases"][0]["redelivered"]["zero_private_evaluation_work"][
            "yao_evaluations"
        ] = 1
        self.assert_rejected_export_delivery(work)

        unknown = copy.deepcopy(self.export_delivery_corpus)
        unknown["cases"][0]["redelivered"]["extra"] = 0
        self.assert_rejected_export_delivery(unknown)

        reordered = {
            "protocol_id": self.export_delivery_corpus["protocol_id"],
            "schema": self.export_delivery_corpus["schema"],
            "evidence_scope": self.export_delivery_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.export_delivery_corpus["cases"]),
        }
        self.assert_rejected_export_delivery(reordered)

    def test_activation_delivery_accepts_canonical_dispatch_and_requires_companions(
        self,
    ) -> None:
        self.assertEqual(
            verify_vectors.verify_activation_delivery_corpus(
                self.activation_delivery_corpus,
                self.semantic_lifecycle_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
                self.output_party_views_corpus,
            ),
            3,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                self.activation_delivery_corpus,
                ceremony_context_corpus=self.ceremony_context_corpus,
                provenance_corpus=self.provenance_corpus,
                semantic_lifecycle_corpus=self.semantic_lifecycle_corpus,
                output_party_views_corpus=self.output_party_views_corpus,
            ),
            3,
        )
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_document(self.activation_delivery_corpus)

    def test_activation_delivery_rejects_origin_and_semantic_identity_mutations(
        self,
    ) -> None:
        reordered = copy.deepcopy(self.activation_delivery_corpus)
        reordered["cases"][0], reordered["cases"][1] = (
            reordered["cases"][1],
            reordered["cases"][0],
        )
        self.assert_rejected_activation_delivery(reordered)

        package = copy.deepcopy(self.activation_delivery_corpus)
        package["cases"][1]["metadata_consumed"]["package_set_digest_hex"] = (
            "00" * 32
        )
        self.assert_rejected_activation_delivery(package)

        transcript = copy.deepcopy(self.activation_delivery_corpus)
        transcript["cases"][2]["activation_control_admitted"][
            "transcript_digest_hex"
        ] = "00" * 32
        self.assert_rejected_activation_delivery(transcript)

    def test_activation_delivery_rejects_authorization_timeline_mutations(self) -> None:
        mutations = (
            ("output_committed", "consumed"),
            ("activation_control_admitted", "not_issued"),
            ("metadata_consumed", "unconsumed"),
            ("delivery_uncertain", "unconsumed"),
            ("recipients_released", "unconsumed"),
            ("redelivered", "unconsumed"),
        )
        for stage, state in mutations:
            with self.subTest(stage=stage):
                mutated = copy.deepcopy(self.activation_delivery_corpus)
                mutated["cases"][0][stage]["activation_authorization_state"] = state
                self.assert_rejected_activation_delivery(mutated)

    def test_activation_delivery_rejects_capability_and_client_scalar_mutations(
        self,
    ) -> None:
        scalar = copy.deepcopy(self.activation_delivery_corpus)
        scalar["cases"][0]["recipients_released"]["client"][
            "x_client_base_hex"
        ] = "00" * 32
        self.assert_rejected_activation_delivery(scalar)

        capability = copy.deepcopy(self.activation_delivery_corpus)
        capability["cases"][1]["recipients_released"]["signing_worker"][
            "capability_kind"
        ] = "activation_client_scalar_release"
        self.assert_rejected_activation_delivery(capability)

        for role in ("client", "signing_worker"):
            with self.subTest(role=role):
                evidence = copy.deepcopy(self.activation_delivery_corpus)
                evidence["cases"][2]["recipients_released"][role][
                    "delivery_evidence_digest_hex"
                ] = "00" * 32
                self.assert_rejected_activation_delivery(evidence)

        cross_output = copy.deepcopy(self.activation_delivery_corpus)
        cross_output["cases"][0]["recipients_released"]["client"][
            "package_set_digest_hex"
        ] = cross_output["cases"][1]["recipients_released"][
            "package_set_digest_hex"
        ]
        self.assert_rejected_activation_delivery(cross_output)

    def test_activation_delivery_rejects_redelivery_zero_work_and_shape_mutations(
        self,
    ) -> None:
        redelivery = copy.deepcopy(self.activation_delivery_corpus)
        redelivery["cases"][0]["redelivered"]["after_client_scalar_hex"] = (
            "00" * 32
        )
        self.assert_rejected_activation_delivery(redelivery)

        work = copy.deepcopy(self.activation_delivery_corpus)
        work["cases"][1]["delivery_uncertain"]["zero_private_evaluation_work"][
            "output_share_samples"
        ] = 1
        self.assert_rejected_activation_delivery(work)

        unknown = copy.deepcopy(self.activation_delivery_corpus)
        unknown["cases"][2]["recipients_released"]["extra"] = 0
        self.assert_rejected_activation_delivery(unknown)

        forbidden = copy.deepcopy(self.activation_delivery_corpus)
        forbidden["cases"][0]["redelivered"]["signing_worker_scalar_hex"] = (
            "11" * 32
        )
        self.assert_rejected_activation_delivery(forbidden)

        reordered_root = {
            "protocol_id": self.activation_delivery_corpus["protocol_id"],
            "schema": self.activation_delivery_corpus["schema"],
            "evidence_scope": self.activation_delivery_corpus["evidence_scope"],
            "cases": copy.deepcopy(self.activation_delivery_corpus["cases"]),
        }
        self.assert_rejected_activation_delivery(reordered_root)

    def test_activation_recipient_party_views_accept_canonical_and_require_companions(
        self,
    ) -> None:
        self.assertEqual(
            verify_vectors.verify_activation_recipient_party_views_corpus(
                self.activation_recipient_party_views_corpus,
                self.ceremony_context_corpus,
                self.provenance_corpus,
                self.semantic_lifecycle_corpus,
                self.output_party_views_corpus,
                self.activation_delivery_corpus,
            ),
            3,
        )
        companions = {
            "ceremony_context_corpus": self.ceremony_context_corpus,
            "provenance_corpus": self.provenance_corpus,
            "semantic_lifecycle_corpus": self.semantic_lifecycle_corpus,
            "output_party_views_corpus": self.output_party_views_corpus,
            "activation_delivery_corpus": self.activation_delivery_corpus,
        }
        self.assertEqual(
            verify_vectors.verify_document(
                self.activation_recipient_party_views_corpus, **companions
            ),
            3,
        )
        for missing in companions:
            with self.subTest(missing=missing):
                incomplete = dict(companions)
                del incomplete[missing]
                with self.assertRaises(verify_vectors.VerificationError):
                    verify_vectors.verify_document(
                        self.activation_recipient_party_views_corpus, **incomplete
                    )

    def test_activation_recipient_party_views_reject_shape_case_and_stage_order_mutations(
        self,
    ) -> None:
        reordered_cases = copy.deepcopy(self.activation_recipient_party_views_corpus)
        reordered_cases["cases"][0], reordered_cases["cases"][1] = (
            reordered_cases["cases"][1],
            reordered_cases["cases"][0],
        )
        self.assert_rejected_activation_recipient_party_views(reordered_cases)

        case_id = copy.deepcopy(self.activation_recipient_party_views_corpus)
        case_id["cases"][0]["case_id"] = "changed"
        self.assert_rejected_activation_recipient_party_views(case_id)

        stage = copy.deepcopy(self.activation_recipient_party_views_corpus)
        stage["cases"][1]["recipients_released"]["common_public"][
            "stage"
        ] = "signing_worker_activated"
        self.assert_rejected_activation_recipient_party_views(stage)

        reordered_stage = copy.deepcopy(self.activation_recipient_party_views_corpus)
        original = reordered_stage["cases"][0]["recipients_released"]
        reordered_stage["cases"][0]["recipients_released"] = {
            "role_extensions": copy.deepcopy(original["role_extensions"]),
            "common_public": copy.deepcopy(original["common_public"]),
        }
        self.assert_rejected_activation_recipient_party_views(reordered_stage)

        reordered_root = {
            "protocol_id": self.activation_recipient_party_views_corpus["protocol_id"],
            "schema": self.activation_recipient_party_views_corpus["schema"],
            "evidence_scope": self.activation_recipient_party_views_corpus[
                "evidence_scope"
            ],
            "cases": copy.deepcopy(
                self.activation_recipient_party_views_corpus["cases"]
            ),
        }
        self.assert_rejected_activation_recipient_party_views(reordered_root)

    def test_activation_recipient_party_views_reject_release_and_custody_mutations(
        self,
    ) -> None:
        mutations: list[dict[str, Any]] = []
        package = copy.deepcopy(self.activation_recipient_party_views_corpus)
        package["cases"][0]["recipients_released"]["common_public"][
            "package_set_digest_hex"
        ] = "00" * 32
        mutations.append(package)
        authorization = copy.deepcopy(self.activation_recipient_party_views_corpus)
        authorization["cases"][1]["recipients_released"]["common_public"][
            "activation_authorization_state"
        ] = "unconsumed"
        mutations.append(authorization)
        work = copy.deepcopy(self.activation_recipient_party_views_corpus)
        work["cases"][2]["recipients_released"]["common_public"][
            "zero_private_evaluation_work"
        ]["yao_evaluations"] = 1
        mutations.append(work)
        client = copy.deepcopy(self.activation_recipient_party_views_corpus)
        client["cases"][0]["recipients_released"]["role_extensions"]["client"][
            "x_client_base_hex"
        ] = "00" * 32
        mutations.append(client)
        authority = copy.deepcopy(self.activation_recipient_party_views_corpus)
        authority["cases"][1]["recipients_released"]["role_extensions"][
            "signing_worker"
        ]["delivery_evidence_digest_hex"] = "00" * 32
        mutations.append(authority)
        infrastructure = copy.deepcopy(self.activation_recipient_party_views_corpus)
        infrastructure["cases"][2]["recipients_released"]["role_extensions"][
            "router"
        ]["x_client_base_hex"] = "00" * 32
        mutations.append(infrastructure)
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected_activation_recipient_party_views(mutated)

    def test_activation_recipient_party_views_reject_activated_scalar_and_identity_mutations(
        self,
    ) -> None:
        mutations: list[dict[str, Any]] = []
        scalar = copy.deepcopy(self.activation_recipient_party_views_corpus)
        scalar["cases"][0]["signing_worker_activated"]["role_extensions"][
            "signing_worker"
        ]["x_server_base_hex"] = "00" * 32
        mutations.append(scalar)
        point = copy.deepcopy(self.activation_recipient_party_views_corpus)
        point["cases"][1]["signing_worker_activated"]["common_public"][
            "x_server_hex"
        ] = "01" + "00" * 31
        mutations.append(point)
        key = copy.deepcopy(self.activation_recipient_party_views_corpus)
        key["cases"][2]["signing_worker_activated"]["common_public"][
            "registered_public_key_hex"
        ] = "01" + "00" * 31
        mutations.append(key)
        epoch = copy.deepcopy(self.activation_recipient_party_views_corpus)
        epoch["cases"][0]["signing_worker_activated"]["common_public"][
            "activation_epoch"
        ] += 1
        mutations.append(epoch)
        worker = copy.deepcopy(self.activation_recipient_party_views_corpus)
        worker["cases"][1]["signing_worker_activated"]["common_public"][
            "signing_worker_recipient_key_epoch"
        ] += 1
        mutations.append(worker)
        client_retention = copy.deepcopy(self.activation_recipient_party_views_corpus)
        client_retention["cases"][2]["signing_worker_activated"]["role_extensions"][
            "client"
        ]["delivery_evidence_digest_hex"] = "ff" * 32
        mutations.append(client_retention)
        for index, mutated in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected_activation_recipient_party_views(mutated)

    def test_activation_recipient_party_views_reject_receipt_digest_key_and_signature_mutations(
        self,
    ) -> None:
        fields = (
            ("activation_receipt_encoding_hex", "00"),
            ("activation_receipt_digest_hex", "00" * 32),
            ("receipt_key_digest_hex", "00" * 32),
            ("receipt_verifying_key_hex", "01" + "00" * 31),
            ("activation_receipt_signature_hex", "00" * 64),
            ("output_storage_evidence_digest_hex", "00" * 32),
        )
        for index, (field, replacement) in enumerate(fields):
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.activation_recipient_party_views_corpus)
                mutated["cases"][index % 3]["signing_worker_activated"][
                    "common_public"
                ][field] = replacement
                self.assert_rejected_activation_recipient_party_views(mutated)

        key_epoch = copy.deepcopy(self.activation_recipient_party_views_corpus)
        key_epoch["cases"][0]["signing_worker_activated"]["common_public"][
            "receipt_key_epoch"
        ] = 0
        self.assert_rejected_activation_recipient_party_views(key_epoch)

        coherent_substitution = copy.deepcopy(
            self.activation_recipient_party_views_corpus
        )
        common = coherent_substitution["cases"][0]["signing_worker_activated"][
            "common_public"
        ]
        substituted_key, _ = _sign_ed25519(b"\x91" * 32, b"")
        key_digest = hashlib.sha256(
            _lp32_join(
                (
                    verify_vectors.SIGNING_WORKER_RECEIPT_KEY_DIGEST_DOMAIN_V1,
                    common["signing_worker_id"].encode("ascii"),
                    common["signing_worker_recipient_key_epoch"].to_bytes(8, "big"),
                    substituted_key,
                )
            )
        ).digest()
        receipt_fields = list(
            verify_vectors._parse_lp32_fields(
                bytes.fromhex(common["activation_receipt_encoding_hex"]),
                22,
                "$coherent_substitution.receipt",
            )
        )
        receipt_fields[2] = key_digest
        receipt_encoding = _lp32_join(tuple(receipt_fields))
        receipt_digest = hashlib.sha256(
            _lp32_join(
                (
                    verify_vectors.SIGNING_WORKER_ACTIVATION_RECEIPT_DIGEST_DOMAIN_V1,
                    receipt_encoding,
                )
            )
        ).digest()
        substituted_key, signature = _sign_ed25519(b"\x91" * 32, receipt_encoding)
        common["receipt_verifying_key_hex"] = substituted_key.hex()
        common["receipt_key_digest_hex"] = key_digest.hex()
        common["activation_receipt_encoding_hex"] = receipt_encoding.hex()
        common["activation_receipt_digest_hex"] = receipt_digest.hex()
        common["activation_receipt_signature_hex"] = signature.hex()
        self.assert_rejected_activation_recipient_party_views(coherent_substitution)

    def test_activation_recipient_party_views_reject_cross_origin_and_recipient_splices(
        self,
    ) -> None:
        release_splice = copy.deepcopy(self.activation_recipient_party_views_corpus)
        release_splice["cases"][0]["recipients_released"]["role_extensions"][
            "signing_worker"
        ] = copy.deepcopy(
            release_splice["cases"][1]["recipients_released"]["role_extensions"][
                "signing_worker"
            ]
        )
        self.assert_rejected_activation_recipient_party_views(release_splice)

        activated_splice = copy.deepcopy(self.activation_recipient_party_views_corpus)
        activated_splice["cases"][1]["signing_worker_activated"] = copy.deepcopy(
            activated_splice["cases"][2]["signing_worker_activated"]
        )
        self.assert_rejected_activation_recipient_party_views(activated_splice)

        recipient_swap = copy.deepcopy(self.activation_recipient_party_views_corpus)
        roles = recipient_swap["cases"][2]["recipients_released"]["role_extensions"]
        roles["signing_worker"] = copy.deepcopy(roles["client"])
        self.assert_rejected_activation_recipient_party_views(recipient_swap)

        delivery_id = copy.deepcopy(self.activation_recipient_party_views_corpus)
        delivery_id["cases"][0]["activation_delivery_case_id"] = (
            "recovery_activation_delivery_v1"
        )
        self.assert_rejected_activation_recipient_party_views(delivery_id)

        output_id = copy.deepcopy(self.activation_recipient_party_views_corpus)
        output_id["cases"][1]["output_party_view_case_id"] = (
            "refresh_output_party_views_package_prepared_v1"
        )
        self.assert_rejected_activation_recipient_party_views(output_id)

    def test_activation_recipient_party_views_reject_forbidden_frames_durable_and_opener_fields(
        self,
    ) -> None:
        insertions = (
            ("recipients_released", "common_public", "frame_bytes_hex", "00"),
            ("recipients_released", "common_public", "durable_record", {}),
            ("recipients_released", "role_extensions", "opener_state_hex", "00"),
            (
                "signing_worker_activated",
                "role_extensions",
                "signing_worker_scalar_share_hex",
                "00" * 32,
            ),
            (
                "signing_worker_activated",
                "common_public",
                "ciphertext_bytes_hex",
                "00",
            ),
            (
                "signing_worker_activated",
                "common_public",
                "security_profile",
                "p0",
            ),
        )
        for stage, container, field, value in insertions:
            with self.subTest(field=field):
                mutated = copy.deepcopy(self.activation_recipient_party_views_corpus)
                target = mutated["cases"][0][stage][container]
                if container == "role_extensions":
                    target = target["signing_worker"]
                target[field] = value
                self.assert_rejected_activation_recipient_party_views(mutated)

        misplaced_scalar = copy.deepcopy(self.activation_recipient_party_views_corpus)
        misplaced_scalar["cases"][0]["recipients_released"]["role_extensions"][
            "signing_worker"
        ]["x_server_base_hex"] = "00" * 32
        self.assert_rejected_activation_recipient_party_views(misplaced_scalar)


SEMANTIC_FRAME_CORPUS_PATH = (
    Path(__file__).resolve().parent.parent
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-semantic-frame-party-views-v1.json"
)
SEMANTIC_FRAME_SOURCE_DIRECTORY = SEMANTIC_FRAME_CORPUS_PATH.parent
SEMANTIC_FRAME_NONCLAIMS = (
    "runtime_frame_encoding",
    "authenticated_transport",
    "production_role_view_serialization",
    "secret_values",
    "excluded_corruption_compositions",
    "profile_negotiation",
    "simulator_or_security_theorem",
    "production_constant_time_or_erasure",
)


def _semantic_frame_test_selector(
    catalog: dict[str, dict[str, set[str]]], schema: str, request_kind: str
) -> str:
    preferred = {
        (verify_vectors.LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1, "refresh"):
            "refresh_opposite_delta_continuity_v1",
    }
    selected = preferred.get((schema, request_kind))
    if selected is not None:
        return selected
    for selector, applicable in sorted(catalog[schema].items()):
        if request_kind in applicable:
            return selector
    raise AssertionError(f"test source corpus {schema!r} has no {request_kind!r} selector")


def _semantic_frame_test_source_references(
    catalog: dict[str, dict[str, set[str]]], request_kind: str, outcome: str
) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    for schema in verify_vectors._semantic_frame_required_source_schemas(
        request_kind, outcome
    ):
        references.append(
            {
                "artifact_kind": verify_vectors.SEMANTIC_FRAME_SCHEMA_ARTIFACT_KINDS[
                    schema
                ],
                "schema": schema,
                "case_selector": _semantic_frame_test_selector(
                    catalog, schema, request_kind
                ),
            }
        )
    return references


def _semantic_frame_test_identity_labels(
    state: str, request_kind: str
) -> list[str]:
    return list(
        verify_vectors._semantic_frame_expected_identity_labels(state, request_kind)
    )


def _semantic_frame_test_case(
    catalog: dict[str, dict[str, set[str]]],
    case_id: str,
    request_kind: str,
    outcome: str,
) -> dict[str, Any]:
    states = verify_vectors._semantic_frame_expected_states(request_kind, outcome)
    observations: dict[str, list[str]] = {
        role: [] for role in verify_vectors.SEMANTIC_FRAME_ROLES
    }
    steps: list[dict[str, Any]] = []
    for ordinal, state in enumerate(states):
        frames = verify_vectors._semantic_frame_emitted_frames(state, request_kind)
        for frame in frames:
            for role in verify_vectors.SEMANTIC_FRAME_OBSERVERS[frame]:
                if frame not in observations[role]:
                    observations[role].append(frame)
        views = []
        for role in verify_vectors.SEMANTIC_FRAME_ROLES:
            views.append(
                {
                    "role": role,
                    "known_values": list(
                        verify_vectors._semantic_frame_expected_known_values(
                            role, state, request_kind
                        )
                    ),
                    "observed_frame_classes": list(observations[role]),
                }
            )
        steps.append(
            {
                "ordinal": ordinal,
                "delivery_state": state,
                "emitted_frame_classes": list(frames),
                "ordered_role_views": views,
                "identity_labels": _semantic_frame_test_identity_labels(
                    state, request_kind
                ),
            }
        )
    evaluator_retry = (
        "terminal_abort_no_resume" if outcome == "evaluator_abort" else "not_applicable"
    )
    redelivery = "not_applicable"
    if outcome == "success":
        redelivery = (
            "exact_export_client_redelivery"
            if request_kind == "export"
            else "exact_activation_recipient_redelivery"
        )
    fresh = [] if outcome == "success" else ["request_identity", "execution_identity"]
    return {
        "case_id": case_id,
        "request_kind": request_kind,
        "outcome": outcome,
        "source_references": _semantic_frame_test_source_references(
            catalog, request_kind, outcome
        ),
        "trace_steps": steps,
        "retry_redelivery_policy": {
            "evaluator_retry": evaluator_retry,
            "redelivery": redelivery,
            "fresh_identity_requirements": fresh,
        },
        "explicit_nonclaims": list(SEMANTIC_FRAME_NONCLAIMS),
    }


def _semantic_frame_test_corpus() -> dict[str, Any]:
    if SEMANTIC_FRAME_CORPUS_PATH.exists():
        return verify_vectors.load_corpus(SEMANTIC_FRAME_CORPUS_PATH)
    catalog = verify_vectors._semantic_frame_source_catalog(
        SEMANTIC_FRAME_SOURCE_DIRECTORY
    )
    cases = [
        _semantic_frame_test_case(catalog, case_id, request_kind, outcome)
        for case_id, request_kind, outcome in verify_vectors.SEMANTIC_FRAME_CASES
    ]
    return {
        "schema": verify_vectors.SEMANTIC_FRAME_PARTY_VIEWS_CORPUS_SCHEMA_V1,
        "protocol_id": verify_vectors.PROTOCOL_ID_V1,
        "evidence_scope": verify_vectors.SEMANTIC_FRAME_PARTY_VIEWS_EVIDENCE_SCOPE_V1,
        "ordered_roles": list(verify_vectors.SEMANTIC_FRAME_ROLES),
        "frame_classes": list(verify_vectors.SEMANTIC_FRAME_CLASSES),
        "delivery_states": list(verify_vectors.SEMANTIC_FRAME_DELIVERY_STATES),
        "corruption_markers": list(
            verify_vectors.SEMANTIC_FRAME_CORRUPTION_MARKERS
        ),
        "interface_shapes": list(verify_vectors.SEMANTIC_FRAME_INTERFACE_SHAPES),
        "cases": cases,
    }


class SemanticFramePartyViewsVerifierTests(unittest.TestCase):
    def assert_semantic_frame_rejected(self, corpus: dict[str, Any]) -> None:
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_semantic_frame_party_views_corpus(
                corpus, SEMANTIC_FRAME_SOURCE_DIRECTORY
            )

    def test_semantic_frame_party_views_reproduces_all_eight_cases(self) -> None:
        corpus = _semantic_frame_test_corpus()
        self.assertEqual(
            verify_vectors.verify_semantic_frame_party_views_corpus(
                corpus, SEMANTIC_FRAME_SOURCE_DIRECTORY
            ),
            8,
        )
        self.assertEqual(
            verify_vectors.verify_document(
                corpus, source_vector_directory=SEMANTIC_FRAME_SOURCE_DIRECTORY
            ),
            8,
        )

    def test_semantic_frame_party_views_rejects_schema_universe_and_case_order_drift(self) -> None:
        schema = _semantic_frame_test_corpus()
        schema["schema"] = "wrong"
        roles = _semantic_frame_test_corpus()
        roles["ordered_roles"][0], roles["ordered_roles"][1] = (
            roles["ordered_roles"][1],
            roles["ordered_roles"][0],
        )
        frames = _semantic_frame_test_corpus()
        frames["frame_classes"].pop()
        states = _semantic_frame_test_corpus()
        states["delivery_states"].append("unknown")
        cases = _semantic_frame_test_corpus()
        cases["cases"][0], cases["cases"][1] = cases["cases"][1], cases["cases"][0]
        for mutated in (schema, roles, frames, states, cases):
            self.assert_semantic_frame_rejected(mutated)

    def test_semantic_frame_party_views_rejects_state_frame_and_terminal_abort_drift(self) -> None:
        state = _semantic_frame_test_corpus()
        state["cases"][0]["trace_steps"][3]["delivery_state"] = "evaluator_aborted"
        frame = _semantic_frame_test_corpus()
        frame["cases"][0]["trace_steps"][4]["emitted_frame_classes"] = [
            "router_to_deriver_a_input_delivery"
        ]
        abort_output = _semantic_frame_test_corpus()
        abort_output["cases"][4]["trace_steps"].insert(
            3, copy.deepcopy(abort_output["cases"][0]["trace_steps"][3])
        )
        abort_resume = _semantic_frame_test_corpus()
        abort_resume["cases"][4]["trace_steps"].append(
            copy.deepcopy(abort_resume["cases"][0]["trace_steps"][4])
        )
        for mutated in (state, frame, abort_output, abort_resume):
            self.assert_semantic_frame_rejected(mutated)

    def test_semantic_frame_party_views_rejects_nonmonotonic_and_cross_role_learning(self) -> None:
        missing = _semantic_frame_test_corpus()
        missing["cases"][0]["trace_steps"][3]["ordered_role_views"][0][
            "known_values"
        ].pop()
        reordering = _semantic_frame_test_corpus()
        known = reordering["cases"][0]["trace_steps"][3]["ordered_role_views"][0][
            "known_values"
        ]
        known[-1], known[-2] = known[-2], known[-1]
        leak = _semantic_frame_test_corpus()
        leak["cases"][0]["trace_steps"][3]["ordered_role_views"][1][
            "known_values"
        ].append("deriver_a_activation_output_shares")
        observer = _semantic_frame_test_corpus()
        observer["cases"][0]["trace_steps"][3]["ordered_role_views"][5][
            "known_values"
        ].append("client_role_scoped_inputs")
        for mutated in (missing, reordering, leak, observer):
            self.assert_semantic_frame_rejected(mutated)

    def test_semantic_frame_party_views_rejects_observation_ownership_diagnostics_and_redelivery_drift(self) -> None:
        owner = _semantic_frame_test_corpus()
        owner["cases"][0]["trace_steps"][2]["ordered_role_views"][2][
            "observed_frame_classes"
        ].append("deriver_a_to_deriver_b_peer_protocol")
        diagnostics = _semantic_frame_test_corpus()
        diagnostics["cases"][0]["trace_steps"][3]["ordered_role_views"][6][
            "observed_frame_classes"
        ].pop()
        observer = _semantic_frame_test_corpus()
        observer["cases"][0]["trace_steps"][0]["ordered_role_views"][5][
            "observed_frame_classes"
        ].append("client_to_router_evaluation_request")
        redelivery = _semantic_frame_test_corpus()
        redelivery["cases"][0]["trace_steps"][7]["ordered_role_views"][2][
            "observed_frame_classes"
        ].append("router_to_client_recipient_delivery")
        for mutated in (owner, diagnostics, observer, redelivery):
            self.assert_semantic_frame_rejected(mutated)

    def test_semantic_frame_party_views_rejects_identity_retry_and_redelivery_policy_drift(self) -> None:
        missing_identity = _semantic_frame_test_corpus()
        missing_identity["cases"][0]["trace_steps"][2]["identity_labels"].pop(0)
        reordered_identity = _semantic_frame_test_corpus()
        labels = reordered_identity["cases"][0]["trace_steps"][3][
            "identity_labels"
        ]
        labels[-1], labels[-2] = labels[-2], labels[-1]
        inapplicable_identity = _semantic_frame_test_corpus()
        inapplicable_identity["cases"][3]["trace_steps"][4][
            "identity_labels"
        ].append("activation_control_identity")
        retry = _semantic_frame_test_corpus()
        retry["cases"][4]["retry_redelivery_policy"]["evaluator_retry"] = (
            "fresh_trace_required"
        )
        fresh = _semantic_frame_test_corpus()
        fresh["cases"][4]["retry_redelivery_policy"][
            "fresh_identity_requirements"
        ] = []
        redelivery = _semantic_frame_test_corpus()
        redelivery["cases"][3]["retry_redelivery_policy"]["redelivery"] = (
            "exact_activation_recipient_redelivery"
        )
        for mutated in (
            missing_identity,
            reordered_identity,
            inapplicable_identity,
            retry,
            fresh,
            redelivery,
        ):
            self.assert_semantic_frame_rejected(mutated)

    def test_semantic_frame_party_views_rejects_corruption_interface_nonclaim_and_forbidden_drift(self) -> None:
        corruption = _semantic_frame_test_corpus()
        corruption["corruption_markers"][1], corruption["corruption_markers"][2] = (
            corruption["corruption_markers"][2],
            corruption["corruption_markers"][1],
        )
        interface = _semantic_frame_test_corpus()
        interface["interface_shapes"].pop()
        nonclaim = _semantic_frame_test_corpus()
        nonclaim["cases"][0]["explicit_nonclaims"] = ["runtime_frame_encoding"]
        forbidden = _semantic_frame_test_corpus()
        forbidden["cases"][0]["runtime_frame_bytes"] = []
        for mutated in (corruption, interface, nonclaim, forbidden):
            self.assert_semantic_frame_rejected(mutated)

    def test_semantic_frame_party_views_rejects_missing_mismatched_and_inapplicable_source_crosslinks(self) -> None:
        missing = _semantic_frame_test_corpus()
        missing["cases"][0]["source_references"].pop()
        schema = _semantic_frame_test_corpus()
        schema["cases"][0]["source_references"][0]["schema"] = (
            verify_vectors.PROVENANCE_VECTOR_CORPUS_SCHEMA_V1
        )
        selector = _semantic_frame_test_corpus()
        selector["cases"][0]["source_references"][0]["case_selector"] = "missing"
        inapplicable = _semantic_frame_test_corpus()
        inapplicable["cases"][0]["source_references"][0]["case_selector"] = (
            "ceremony-recovery-v1"
        )
        for mutated in (missing, schema, selector, inapplicable):
            self.assert_semantic_frame_rejected(mutated)
        with self.assertRaises(verify_vectors.VerificationError):
            verify_vectors.verify_semantic_frame_party_views_corpus(
                _semantic_frame_test_corpus(), None
            )


if __name__ == "__main__":
    unittest.main()

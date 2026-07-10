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
LIFECYCLE_REFRESH_DELTA_KEY_ORDER = ("delta_y_hex", "delta_tau_hex")
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
LIFECYCLE_RECOVERY_ACTIVATION_KEY_ORDER = (
    "case_id",
    "origin_case_id",
    "pending_public",
    "activated_public",
    "reference_operation_counts",
)
LIFECYCLE_REFRESH_ACTIVATION_KEY_ORDER = LIFECYCLE_RECOVERY_ACTIVATION_KEY_ORDER

LIFECYCLE_CASE_SEQUENCE_V1 = (
    ("recovery", "recovery_same_root_continuity_v1"),
    ("activation", "activation_after_recovery_zero_evaluation_v1"),
    ("refresh", "refresh_opposite_delta_continuity_v1"),
    ("activation", "activation_after_refresh_zero_evaluation_v1"),
)
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


def _compress_point(point: Point) -> bytes:
    x, y, z, _ = point
    inverse_z = _field_inverse(z)
    affine_x = (x * inverse_z) % FIELD_PRIME
    affine_y = (y * inverse_z) % FIELD_PRIME
    encoded = affine_y | ((affine_x & 1) << 255)
    return encoded.to_bytes(32, "little")


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
        encoded = corpus_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise VerificationError(f"cannot read {corpus_path}: {error}") from error
    return parse_corpus_json(encoded)


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise VerificationError(f"{path} must be a JSON object")
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
    delta_y = _decode_hex(delta["delta_y_hex"], 32, f"{delta_path}.delta_y_hex")
    delta_tau = _decode_scalar(delta["delta_tau_hex"], f"{delta_path}.delta_tau_hex")
    if delta_y == bytes(32):
        raise VerificationError(f"{delta_path}.delta_y_hex must be nonzero")
    if delta_tau == 0:
        raise VerificationError(f"{delta_path}.delta_tau_hex must be nonzero")
    if delta_y != LIFECYCLE_DELTA_Y_V1:
        raise VerificationError(f"{delta_path}.delta_y_hex is not the canonical fixture delta")
    if delta_tau != LIFECYCLE_DELTA_TAU_V1:
        raise VerificationError(f"{delta_path}.delta_tau_hex is not the canonical fixture delta")

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
    if origin_kind not in {"recovery", "refresh"}:
        raise VerificationError(f"{path}.origin_kind is unsupported")
    _require_exact_value(origin_kind, expected_origin_kind, f"{path}.origin_kind")
    transition_path = f"{path}.transition"
    transition_order = (
        LIFECYCLE_RECOVERY_ACTIVATION_KEY_ORDER
        if origin_kind == "recovery"
        else LIFECYCLE_REFRESH_ACTIVATION_KEY_ORDER
    )
    transition = _require_ordered_keys(
        activation["transition"], transition_order, transition_path
    )
    origin_case_id = _require_string(
        transition["origin_case_id"], f"{transition_path}.origin_case_id"
    )
    expected_origin_case_id = (
        "recovery_same_root_continuity_v1"
        if origin_kind == "recovery"
        else "refresh_opposite_delta_continuity_v1"
    )
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

    if origin_kind == "recovery":
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
    """Independently verifies the strict four-case host lifecycle corpus."""
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
        raise VerificationError("$.cases must contain exactly four lifecycle cases")

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
        if request_kind not in {"recovery", "activation", "refresh"}:
            raise VerificationError(f"{case_path}.request_kind is unsupported")
        _require_exact_value(request_kind, expected_kind, f"{case_path}.request_kind")

        vector_path = f"{case_path}.vector"
        if request_kind == "recovery":
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
            expected_origin_kind = "recovery" if index == 1 else "refresh"
            _verify_activation_lifecycle_case(
                activation, expected_origin_kind, prior_cases, vector_path
            )
        if case_id in case_ids:
            raise VerificationError(f"{case_path} duplicates case id {case_id!r}")
        case_ids.add(case_id)

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


def verify_document(document: Any, *, differential_seed: bytes | None = None) -> int:
    """Auto-detects and verifies one supported strict v1 corpus schema."""
    document_object = _require_object(document, "$")
    schema = _require_string(document_object.get("schema"), "$.schema")
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
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parse_arguments(arguments)
    try:
        differential_seed = None
        if options.differential_seed_hex is not None:
            differential_seed = _decode_hex(
                options.differential_seed_hex, 32, "--differential-seed-hex"
            )
        case_count = verify_document(
            load_corpus(options.corpus), differential_seed=differential_seed
        )
    except VerificationError as error:
        print(f"ed25519-yao independent verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified {case_count} independent Ed25519 Yao vector cases in {options.corpus}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

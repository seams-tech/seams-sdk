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

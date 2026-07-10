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
DIFFERENTIAL_SEED_HEX = "5a" * 32
DIFFERENTIAL_SEED = bytes.fromhex(DIFFERENTIAL_SEED_HEX)


def _reference(case: dict[str, Any]) -> dict[str, Any]:
    if case["request_kind"] == "export":
        return case["vector"]["reference"]
    return case["vector"]


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

    recovery_pending = _recovery_pending_state(identity, current_epochs)
    recovery = {
        "case_id": "recovery_same_root_continuity_v1",
        "before_public": _active_state(identity, current_epochs, 7),
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
                "delta_y_hex": delta_y_hex,
                "delta_tau_hex": delta_tau.to_bytes(32, "little").hex(),
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

    def test_lifecycle_corpus_auto_detection_reproduces_all_four_cases(self) -> None:
        self.assertEqual(
            verify_vectors.verify_lifecycle_continuity_corpus(self.lifecycle_corpus), 4
        )
        self.assertEqual(verify_vectors.verify_document(self.lifecycle_corpus), 4)
        if self.committed_lifecycle_corpus is not None:
            self.assertEqual(
                verify_vectors.verify_lifecycle_continuity_corpus(
                    self.committed_lifecycle_corpus
                ),
                4,
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
        unsupported_request["cases"][0]["request_kind"] = "registration"
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
        for field_name in forbidden_fields:
            with self.subTest(field_name=field_name):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][1]["vector"]["transition"][field_name] = {}
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_primitives_reject_malformed_values(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        uppercase = copy.deepcopy(self.lifecycle_corpus)
        uppercase["cases"][0]["vector"]["host_only_reference"]["synthetic_roots"][
            "client_root_hex"
        ] = "AA" * 32
        mutations.append(("uppercase_hex", uppercase))
        short_hex = copy.deepcopy(self.lifecycle_corpus)
        short_hex["cases"][0]["vector"]["host_only_reference"]["synthetic_roots"][
            "client_root_hex"
        ] = "11"
        mutations.append(("short_hex", short_hex))
        noncanonical_scalar = copy.deepcopy(self.lifecycle_corpus)
        noncanonical_scalar["cases"][0]["vector"]["host_only_reference"][
            "current_contributions"
        ]["tau_client_a_hex"] = verify_vectors.SCALAR_ORDER.to_bytes(32, "little").hex()
        mutations.append(("noncanonical_scalar", noncanonical_scalar))
        zero_epoch = copy.deepcopy(self.lifecycle_corpus)
        zero_epoch["cases"][0]["vector"]["before_public"]["active_activation_epoch"] = 0
        mutations.append(("zero_epoch", zero_epoch))
        boolean_epoch = copy.deepcopy(self.lifecycle_corpus)
        boolean_epoch["cases"][0]["vector"]["before_public"]["active_activation_epoch"] = True
        mutations.append(("boolean_epoch", boolean_epoch))
        participants = copy.deepcopy(self.lifecycle_corpus)
        participants["cases"][0]["vector"]["before_public"]["identity"]["context"][
            "participant_ids"
        ] = [2, 1]
        mutations.append(("participants", participants))
        binding = copy.deepcopy(self.lifecycle_corpus)
        binding["cases"][0]["vector"]["before_public"]["identity"][
            "application_binding"
        ]["wallet_id"] = "invalid value"
        mutations.append(("application_binding", binding))
        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_recovery_rejects_changed_root_and_rederived_inputs(self) -> None:
        changed_root = copy.deepcopy(self.lifecycle_corpus)
        changed_root["cases"][0]["vector"]["host_only_reference"][
            "recovered_client_root_hex"
        ] = "12" * 32
        self.assert_rejected_lifecycle(changed_root)

        rederived_fields = verify_vectors.LIFECYCLE_CLIENT_CONTRIBUTION_KEY_ORDER
        for field_name in rederived_fields:
            with self.subTest(field_name=field_name):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][0]["vector"]["host_only_reference"][
                    "rederived_client_contributions"
                ][field_name] = "00" * 32
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_recovery_rejects_any_changed_after_contribution_or_trace(self) -> None:
        for field_name in verify_vectors.LIFECYCLE_CONTRIBUTION_KEY_ORDER:
            with self.subTest(kind="contribution", field_name=field_name):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][0]["vector"]["host_only_reference"][
                    "after_contributions"
                ][field_name] = "00" * 32
                self.assert_rejected_lifecycle(mutated)
        for field_name in verify_vectors.LIFECYCLE_TRACE_KEY_ORDER:
            with self.subTest(kind="trace", field_name=field_name):
                mutated = copy.deepcopy(self.lifecycle_corpus)
                byte_length = 64 if field_name == "sha512_digest_hex" else 32
                mutated["cases"][0]["vector"]["host_only_reference"][
                    "after_clear_reference_trace"
                ][field_name] = "00" * byte_length
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_recovery_rejects_public_identity_and_epoch_drift(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        public_key = copy.deepcopy(self.lifecycle_corpus)
        public_key["cases"][0]["vector"]["pending_public"]["identity"][
            "registered_public_key_hex"
        ] = "00" * 32
        mutations.append(("public_key", public_key))
        root_epoch = copy.deepcopy(self.lifecycle_corpus)
        root_epoch["cases"][0]["vector"]["pending_public"]["current_role_epochs"][
            "deriver_a"
        ]["role_root_epoch"] = 4
        mutations.append(("root_epoch", root_epoch))
        input_epoch = copy.deepcopy(self.lifecycle_corpus)
        input_epoch["cases"][0]["vector"]["pending_public"]["current_role_epochs"][
            "deriver_b"
        ]["role_input_state_epoch"] = 42
        mutations.append(("input_epoch", input_epoch))
        slot = copy.deepcopy(self.lifecycle_corpus)
        slot["cases"][0]["vector"]["pending_public"]["identity"][
            "application_binding"
        ]["key_creation_signer_slot"] = 2
        mutations.append(("slot", slot))
        context = copy.deepcopy(self.lifecycle_corpus)
        context["cases"][0]["vector"]["pending_public"]["identity"]["context"][
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
                mutated["cases"][0]["vector"]["pending_public"][
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
                mutated["cases"][0]["vector"]["reference_operation_counts"][
                    field_name
                ] = value
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_refresh_rejects_zero_and_noncanonical_deltas(self) -> None:
        zero_y = copy.deepcopy(self.lifecycle_corpus)
        zero_y["cases"][2]["vector"]["host_only_reference"]["delta"][
            "delta_y_hex"
        ] = "00" * 32
        self.assert_rejected_lifecycle(zero_y)
        zero_tau = copy.deepcopy(self.lifecycle_corpus)
        zero_tau["cases"][2]["vector"]["host_only_reference"]["delta"][
            "delta_tau_hex"
        ] = "00" * 32
        self.assert_rejected_lifecycle(zero_tau)
        noncanonical_tau = copy.deepcopy(self.lifecycle_corpus)
        noncanonical_tau["cases"][2]["vector"]["host_only_reference"]["delta"][
            "delta_tau_hex"
        ] = verify_vectors.SCALAR_ORDER.to_bytes(32, "little").hex()
        self.assert_rejected_lifecycle(noncanonical_tau)

    def test_lifecycle_refresh_rejects_wrong_delta_application(self) -> None:
        before = self.lifecycle_corpus["cases"][2]["vector"]["host_only_reference"][
            "before_contributions"
        ]
        delta_y = self.lifecycle_corpus["cases"][2]["vector"]["host_only_reference"][
            "delta"
        ]["delta_y_hex"]
        same_sign = copy.deepcopy(self.lifecycle_corpus)
        same_sign["cases"][2]["vector"]["host_only_reference"]["after_contributions"][
            "y_server_b_hex"
        ] = _add_le_256_hex(before["y_server_b_hex"], delta_y)
        self.assert_rejected_lifecycle(same_sign)
        one_sided = copy.deepcopy(self.lifecycle_corpus)
        one_sided["cases"][2]["vector"]["host_only_reference"]["after_contributions"][
            "tau_server_b_hex"
        ] = before["tau_server_b_hex"]
        self.assert_rejected_lifecycle(one_sided)
        swapped_domain = copy.deepcopy(self.lifecycle_corpus)
        swapped_domain["cases"][2]["vector"]["host_only_reference"][
            "after_contributions"
        ]["y_server_a_hex"] = _add_le_256_hex(before["y_server_a_hex"], "11" + "00" * 31)
        self.assert_rejected_lifecycle(swapped_domain)

    def test_lifecycle_refresh_rejects_client_and_trace_identity_changes(self) -> None:
        client = copy.deepcopy(self.lifecycle_corpus)
        client["cases"][2]["vector"]["host_only_reference"]["after_contributions"][
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
                mutated["cases"][2]["vector"]["host_only_reference"][
                    "after_clear_reference_trace"
                ][field_name] = "00" * 32
                self.assert_rejected_lifecycle(mutated)

    def test_lifecycle_refresh_rejects_epoch_and_admission_mutations(self) -> None:
        mutations: list[tuple[str, dict[str, Any]]] = []
        root_epoch = copy.deepcopy(self.lifecycle_corpus)
        root_epoch["cases"][2]["vector"]["pending_public"]["next_role_epochs"][
            "deriver_a"
        ]["role_root_epoch"] = 4
        mutations.append(("root_epoch", root_epoch))
        for role_name, value in (("deriver_a", 11), ("deriver_b", 40), ("deriver_b", 0)):
            mutated = copy.deepcopy(self.lifecycle_corpus)
            mutated["cases"][2]["vector"]["pending_public"]["next_role_epochs"][
                role_name
            ]["role_input_state_epoch"] = value
            mutations.append((f"input_epoch_{role_name}_{value}", mutated))
        for activation_epoch in (8, 7, 0):
            mutated = copy.deepcopy(self.lifecycle_corpus)
            mutated["cases"][2]["vector"]["pending_public"][
                "pending_activation_epoch"
            ] = activation_epoch
            mutations.append((f"activation_epoch_{activation_epoch}", mutated))
        open_pending = copy.deepcopy(self.lifecycle_corpus)
        open_pending["cases"][2]["vector"]["pending_public"][
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
                mutated["cases"][2]["vector"]["reference_operation_counts"][
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
        active_epoch["cases"][3]["vector"]["transition"]["activated_public"][
            "active_role_epochs"
        ]["deriver_a"]["role_input_state_epoch"] = 11
        self.assert_rejected_lifecycle(active_epoch)
        retired = copy.deepcopy(self.lifecycle_corpus)
        retired["cases"][3]["vector"]["transition"]["activated_public"][
            "retired_role_input_state_epochs"
        ]["deriver_b"] = 43
        self.assert_rejected_lifecycle(retired)
        admission = copy.deepcopy(self.lifecycle_corpus)
        admission["cases"][3]["vector"]["transition"]["activated_public"][
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
        for case_index in (1, 3):
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
        for suffix in verify_vectors.LIFECYCLE_PUBLIC_FORBIDDEN_SUFFIXES_V1:
            field_name = suffix if not suffix.startswith("_") else f"secret{suffix}"
            with self.subTest(field_name=field_name):
                with self.assertRaises(verify_vectors.VerificationError):
                    verify_vectors._scan_lifecycle_public_boundary(
                        {"safe": {field_name: "00"}}, "$public"
                    )
                mutated = copy.deepcopy(self.lifecycle_corpus)
                mutated["cases"][0]["vector"]["before_public"][field_name] = "00"
                self.assert_rejected_lifecycle(mutated)

    def assert_rejected_kdf(self, corpus: dict[str, Any], pattern: str) -> None:
        with self.assertRaisesRegex(verify_vectors.VerificationError, pattern):
            verify_vectors.verify_kdf_corpus(corpus)


if __name__ == "__main__":
    unittest.main()

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
DIFFERENTIAL_SEED_HEX = "5a" * 32
DIFFERENTIAL_SEED = bytes.fromhex(DIFFERENTIAL_SEED_HEX)


def _reference(case: dict[str, Any]) -> dict[str, Any]:
    if case["request_kind"] == "export":
        return case["vector"]["reference"]
    return case["vector"]


class IndependentVectorVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = verify_vectors.load_corpus(CORPUS_PATH)
        self.differential_corpus = verify_vectors.load_corpus(DIFFERENTIAL_CORPUS_PATH)
        self.kdf_corpus = verify_vectors.load_corpus(KDF_CORPUS_PATH)

    def assert_rejected(self, corpus: dict[str, Any], pattern: str) -> None:
        with self.assertRaisesRegex(verify_vectors.VerificationError, pattern):
            verify_vectors.verify_corpus(corpus)

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

    def assert_rejected_kdf(self, corpus: dict[str, Any], pattern: str) -> None:
        with self.assertRaisesRegex(verify_vectors.VerificationError, pattern):
            verify_vectors.verify_kdf_corpus(corpus)


if __name__ == "__main__":
    unittest.main()

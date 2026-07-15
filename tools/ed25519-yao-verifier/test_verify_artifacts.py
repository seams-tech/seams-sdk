#!/usr/bin/env python3
"""Mutation tests for the independent Phase 2A artifact verifier."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Callable

import verify_artifacts


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VECTOR_CORPUS = (
    REPOSITORY_ROOT
    / "tools"
    / "ed25519-yao-generator"
    / "vectors"
    / "ed25519-yao-v1.json"
)
SOURCE_VECTOR_DIRECTORY = VECTOR_CORPUS.parent
PHASE2B_RECONCILIATION_CORPUS = (
    SOURCE_VECTOR_DIRECTORY / "ed25519-yao-phase2b-core-reconciliation-v1.json"
)


class IndependentArtifactVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configured = os.environ.get("ED25519_YAO_ARTIFACT_DIR")
        cls._temporary: tempfile.TemporaryDirectory[str] | None = None
        if configured is None:
            cls._temporary = tempfile.TemporaryDirectory(prefix="ed25519-yao-artifacts-")
            temporary_root = Path(cls._temporary.name).resolve(strict=True)
            configured = str(temporary_root / "bundle")
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--locked",
                    "--manifest-path",
                    str(REPOSITORY_ROOT / "tools/ed25519-yao-generator/Cargo.toml"),
                    "--bin",
                    "ed25519-yao-circuit-artifacts",
                    "--",
                    "emit",
                    "--output-dir",
                    configured,
                ],
                cwd=REPOSITORY_ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
        cls.artifact_dir = Path(configured)
        cls.files = {path.name: path.read_bytes() for path in cls.artifact_dir.iterdir()}
        cls.artifacts = {
            name: data
            for name, data in cls.files.items()
            if name != verify_artifacts.INDEX_FILE
        }
        cls.bundle = verify_artifacts.verify_bundle_directory(cls.artifact_dir)
        manifest_hex = subprocess.run(
            [
                "cargo",
                "run",
                "--locked",
                "--quiet",
                "--manifest-path",
                "tools/ed25519-yao-generator/Cargo.toml",
                "--bin",
                "ed25519-yao-benchmark-manifest",
                "--",
                "hex",
            ],
            cwd=REPOSITORY_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        cls.benchmark_manifest = bytes.fromhex(manifest_hex)
        cls._certificate_temporary: tempfile.TemporaryDirectory[str] | None = None
        if PHASE2B_RECONCILIATION_CORPUS.is_file():
            cls.phase2b_certificate = PHASE2B_RECONCILIATION_CORPUS.read_bytes()
        else:
            cls._certificate_temporary = tempfile.TemporaryDirectory(
                prefix="ed25519-yao-phase2b-certificate-"
            )
            certificate_path = (
                Path(cls._certificate_temporary.name) / "phase2b-reconciliation.json"
            )
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--locked",
                    "--quiet",
                    "--manifest-path",
                    "tools/ed25519-yao-generator/Cargo.toml",
                    "--bin",
                    "ed25519-yao-vectors",
                    "--",
                    "emit-phase2b-core-reconciliation",
                    "--output",
                    str(certificate_path),
                ],
                cwd=REPOSITORY_ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            cls.phase2b_certificate = certificate_path.read_bytes()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._temporary is not None:
            cls._temporary.cleanup()
        if cls._certificate_temporary is not None:
            cls._certificate_temporary.cleanup()

    def assert_artifact_rejected(self, action: Callable[[], object]) -> None:
        with self.assertRaises(verify_artifacts.ArtifactVerificationError):
            action()

    def _write_directory(
        self, root: Path, *, missing: str | None = None, extra: bool = False
    ) -> None:
        for filename, data in self.files.items():
            if filename != missing:
                (root / filename).write_bytes(data)
        if extra:
            (root / "unexpected.bin").write_bytes(b"extra")

    def _phase2b_document(self) -> dict[str, object]:
        return json.loads(self.phase2b_certificate.decode("utf-8"))

    def _phase2b_bytes(self, document: dict[str, object]) -> bytes:
        return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode(
            "utf-8"
        )

    def _verify_phase2b(self, certificate: bytes) -> int:
        return verify_artifacts.verify_phase2b_core_reconciliation(
            certificate,
            self.bundle,
            self.benchmark_manifest,
            SOURCE_VECTOR_DIRECTORY,
        )

    def test_artifact_canonical_bundle_and_five_vectors(self) -> None:
        self.assertEqual(
            verify_artifacts.verify_five_case_corpus(self.bundle, VECTOR_CORPUS), 5
        )

    def test_artifact_benchmark_manifest_independently_decodes(self) -> None:
        verify_artifacts.verify_benchmark_manifest(
            self.benchmark_manifest,
            self.files[verify_artifacts.INDEX_FILE],
        )

    def test_artifact_benchmark_manifest_rejects_prefix_mutations(self) -> None:
        for offset in (0, 9, 10, 11):
            mutation = bytearray(self.benchmark_manifest)
            mutation[offset] ^= 1
            with self.subTest(offset=offset):
                self.assert_artifact_rejected(
                    lambda mutation=bytes(mutation): verify_artifacts.verify_benchmark_manifest(
                        mutation,
                        self.files[verify_artifacts.INDEX_FILE],
                    )
                )

    def test_artifact_benchmark_manifest_rejects_component_mutation(self) -> None:
        mutation = bytearray(self.benchmark_manifest)
        mutation[-1] ^= 1
        self.assert_artifact_rejected(
            lambda: verify_artifacts.verify_benchmark_manifest(
                bytes(mutation),
                self.files[verify_artifacts.INDEX_FILE],
            )
        )

    def test_artifact_benchmark_manifest_rejects_index_splice(self) -> None:
        index = bytearray(self.files[verify_artifacts.INDEX_FILE])
        index[-1] ^= 1
        self.assert_artifact_rejected(
            lambda: verify_artifacts.verify_benchmark_manifest(
                self.benchmark_manifest,
                bytes(index),
            )
        )

    def test_artifact_phase2b_reconciliation_valid_certificate(self) -> None:
        self.assertEqual(self._verify_phase2b(self.phase2b_certificate), 5)

    def test_artifact_phase2b_reconciliation_rejects_commitment_and_selector_mutation(
        self,
    ) -> None:
        commitment_mutation = self._phase2b_document()
        commitment_mutation["phase1_corpus_commitments"][0]["sha256_hex"] = "00" * 32
        selector_mutation = self._phase2b_document()
        selector_mutation["cases"][0]["vector"][
            "evaluator_admission_case_id"
        ] = "recovery_admitted_evaluation_output_committed_v1"
        for label, document in (
            ("commitment", commitment_mutation),
            ("selector", selector_mutation),
        ):
            with self.subTest(label=label):
                self.assert_artifact_rejected(
                    lambda document=document: self._verify_phase2b(
                        self._phase2b_bytes(document)
                    )
                )

    def test_artifact_phase2b_reconciliation_rejects_field_order_and_component_splice(
        self,
    ) -> None:
        reordered = self._phase2b_document()
        schema = reordered.pop("schema")
        reordered["schema"] = schema
        mapping_splice = self._phase2b_document()
        fields = mapping_splice["mapping_contracts"]["activation_family"][
            "input_fields"
        ]
        fields[0], fields[1] = fields[1], fields[0]
        component_splice = self._phase2b_document()
        component_splice["cases"][4]["vector"]["component_kind"] = "activation"
        for label, document in (
            ("field_order", reordered),
            ("mapping_order", mapping_splice),
            ("component", component_splice),
        ):
            with self.subTest(label=label):
                self.assert_artifact_rejected(
                    lambda document=document: self._verify_phase2b(
                        self._phase2b_bytes(document)
                    )
                )

    def test_artifact_phase2b_reconciliation_rejects_output_and_zero_evaluation_mutation(
        self,
    ) -> None:
        output_mutation = self._phase2b_document()
        output_mutation["cases"][0]["vector"][
            "party_output_reconstruction_digest_hex"
        ] = "00" * 32
        activation_mutation = self._phase2b_document()
        activation_mutation["cases"][1]["vector"]["evaluation_plan"]["counts"][
            "yao_evaluations"
        ] = 1
        export_mutation = self._phase2b_document()
        export_mutation["cases"][4]["vector"][
            "authorized_client_output_digest_hex"
        ] = "00" * 32
        for label, document in (
            ("party_output", output_mutation),
            ("zero_evaluation", activation_mutation),
            ("authorized_client", export_mutation),
        ):
            with self.subTest(label=label):
                self.assert_artifact_rejected(
                    lambda document=document: self._verify_phase2b(
                        self._phase2b_bytes(document)
                    )
                )

    def test_artifact_frozen_index_ir_and_schedule_digests(self) -> None:
        index = self.files[verify_artifacts.INDEX_FILE]
        self.assertEqual(
            hashlib.sha256(index).digest(),
            verify_artifacts.BUNDLE_INDEX_DIGEST,
        )
        spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        wrong_ir_spec = replace(spec, ir_digest=b"\x00" * 32)
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_ir(
                self.artifacts[spec.ir_file], wrong_ir_spec
            )
        )
        circuit = verify_artifacts.parse_ir(self.artifacts[spec.ir_file], spec)
        wrong_schedule_spec = replace(spec, schedule_digest=b"\x00" * 32)
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_schedule(
                self.artifacts[spec.schedule_file], wrong_schedule_spec, circuit
            )
        )

    def test_artifact_vector_shape_and_hex_are_strict(self) -> None:
        document = json.loads(VECTOR_CORPUS.read_text(encoding="utf-8"))
        document["unexpected"] = True
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as temporary:
            json.dump(document, temporary)
            temporary.flush()
            self.assert_artifact_rejected(
                lambda: verify_artifacts.verify_five_case_corpus(
                    self.bundle, Path(temporary.name)
                )
            )
        document.pop("unexpected")
        document["cases"][0]["vector"]["clear_reference_trace"][
            "x_client_base_hex"
        ] = "GG" * 32
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as temporary:
            json.dump(document, temporary)
            temporary.flush()
            self.assert_artifact_rejected(
                lambda: verify_artifacts.verify_five_case_corpus(
                    self.bundle, Path(temporary.name)
                )
            )

    def test_artifact_directory_rejects_missing_and_extra(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            self._write_directory(root, missing=verify_artifacts.INDEX_FILE)
            self.assert_artifact_rejected(
                lambda: verify_artifacts.verify_bundle_directory(root)
            )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            self._write_directory(root)
            oversized = verify_artifacts.COMPONENT_BY_NAME["export"]
            with (root / oversized.ir_file).open("ab") as output:
                output.write(b"x")
            self.assert_artifact_rejected(
                lambda: verify_artifacts.verify_bundle_directory(root)
            )
        if os.name != "nt":
            with tempfile.TemporaryDirectory() as temporary:
                temporary_root = Path(temporary).resolve(strict=True)
                real_root = temporary_root / "real"
                linked_root = temporary_root / "linked"
                real_root.mkdir()
                self._write_directory(real_root)
                linked_root.symlink_to(real_root, target_is_directory=True)
                self.assert_artifact_rejected(
                    lambda: verify_artifacts.verify_bundle_directory(linked_root)
                )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            self._write_directory(root, extra=True)
            self.assert_artifact_rejected(
                lambda: verify_artifacts.verify_bundle_directory(root)
            )

    @unittest.skipIf(os.name == "nt", "descriptor-relative verifier is Linux/macOS-only")
    def test_artifact_directory_rejects_entry_links_and_ancestor_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            real_parent = root / "real-parent"
            real_root = real_parent / "bundle"
            real_parent.mkdir()
            real_root.mkdir()
            self._write_directory(real_root)

            external = root / "external.bin"
            external.write_bytes(b"external")
            spec = verify_artifacts.COMPONENT_BY_NAME["export"]
            expected = real_root / spec.ir_file
            expected.unlink()
            expected.symlink_to(external)
            self.assert_artifact_rejected(
                lambda: verify_artifacts.verify_bundle_directory(real_root)
            )

            expected.unlink()
            expected.write_bytes(self.files[spec.ir_file])
            external.unlink()
            os.link(expected, external)
            self.assert_artifact_rejected(
                lambda: verify_artifacts.verify_bundle_directory(real_root)
            )
            external.unlink()

            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            self.assert_artifact_rejected(
                lambda: verify_artifacts.verify_bundle_directory(
                    linked_parent / "bundle"
                )
            )

    def test_artifact_index_rejects_magic_tag_and_trailing_bytes(self) -> None:
        canonical = self.files[verify_artifacts.INDEX_FILE]
        for mutation in (
            bytes([canonical[0] ^ 1]) + canonical[1:],
            canonical[:9] + bytes([canonical[9] ^ 1]) + canonical[10:],
            canonical + b"trailing",
        ):
            with self.subTest(mutation=len(mutation)):
                self.assert_artifact_rejected(
                    lambda mutation=mutation: verify_artifacts.verify_index(
                        mutation, self.artifacts
                    )
                )

    def test_artifact_index_rejects_digest_and_length(self) -> None:
        canonical = bytearray(self.files[verify_artifacts.INDEX_FILE])
        filename_length = int.from_bytes(canonical[10:12], "big")
        length_offset = 12 + filename_length
        digest_offset = length_offset + 8
        for offset in (length_offset + 7, digest_offset):
            mutation = bytearray(canonical)
            mutation[offset] ^= 1
            self.assert_artifact_rejected(
                lambda mutation=bytes(mutation): verify_artifacts.verify_index(
                    mutation, self.artifacts
                )
            )

    def test_artifact_ir_rejects_magic_component_schema_and_count(self) -> None:
        spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        canonical = self.artifacts[spec.ir_file]
        for offset in (0, 8, 10, 81):
            mutation = bytearray(canonical)
            mutation[offset] ^= 1
            self.assert_artifact_rejected(
                lambda mutation=bytes(mutation): verify_artifacts.parse_ir(
                    mutation, spec
                )
            )

    def test_artifact_ir_rejects_opcode_and_forward_reference(self) -> None:
        spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        canonical = bytearray(self.artifacts[spec.ir_file])
        bad_opcode = bytearray(canonical)
        bad_opcode[verify_artifacts.IR_HEADER_BYTES] = 0
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_ir(bytes(bad_opcode), spec)
        )
        bad_reference = bytearray(canonical)
        bad_reference[
            verify_artifacts.IR_HEADER_BYTES + 1 : verify_artifacts.IR_HEADER_BYTES + 5
        ] = spec.input_count.to_bytes(4, "big")
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_ir(bytes(bad_reference), spec)
        )

    def test_artifact_ir_rejects_noncanonical_operands_and_inv_shape(self) -> None:
        export_spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        export = bytearray(self.artifacts[export_spec.ir_file])
        for gate_index in range(export_spec.gate_count):
            offset = verify_artifacts.IR_HEADER_BYTES + gate_index * 9
            left = export[offset + 1 : offset + 5]
            right = export[offset + 5 : offset + 9]
            if export[offset] in (1, 2) and left < right:
                export[offset + 1 : offset + 5] = right
                export[offset + 5 : offset + 9] = left
                break
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_ir(bytes(export), export_spec)
        )

        sha_spec = verify_artifacts.COMPONENT_BY_NAME["sha512"]
        sha = bytearray(self.artifacts[sha_spec.ir_file])
        for gate_index in range(sha_spec.gate_count):
            offset = verify_artifacts.IR_HEADER_BYTES + gate_index * 9
            if sha[offset] == 3:
                left = int.from_bytes(sha[offset + 1 : offset + 5], "big")
                output_wire = sha_spec.input_count + gate_index
                replacement = (left + 1) % output_wire
                if replacement == left:
                    replacement = (replacement + 1) % output_wire
                sha[offset + 5 : offset + 9] = replacement.to_bytes(4, "big")
                break
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_ir(bytes(sha), sha_spec)
        )

    def test_artifact_ir_rejects_output_mutation_and_trailing_bytes(self) -> None:
        spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        canonical = self.artifacts[spec.ir_file]
        output_offset = verify_artifacts.IR_HEADER_BYTES + spec.gate_count * 9
        duplicate = bytearray(canonical)
        duplicate[output_offset + 4 : output_offset + 8] = duplicate[
            output_offset : output_offset + 4
        ]
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_ir(bytes(duplicate), spec)
        )
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_ir(canonical + b"trailing", spec)
        )

    def test_artifact_schedule_rejects_magic_tag_and_circuit_digest(self) -> None:
        spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        circuit = verify_artifacts.parse_ir(self.artifacts[spec.ir_file], spec)
        canonical = self.artifacts[spec.schedule_file]
        for offset in (0, 8, 10):
            mutation = bytearray(canonical)
            mutation[offset] ^= 1
            self.assert_artifact_rejected(
                lambda mutation=bytes(mutation): verify_artifacts.parse_schedule(
                    mutation, spec, circuit
                )
            )

    def test_artifact_schedule_rejects_width_length_and_trailing_bytes(self) -> None:
        spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        circuit = verify_artifacts.parse_ir(self.artifacts[spec.ir_file], spec)
        canonical = self.artifacts[spec.schedule_file]
        for mutation in (
            canonical[:9] + b"\x00" + canonical[10:],
            canonical[:-1],
            canonical + b"trailing",
        ):
            self.assert_artifact_rejected(
                lambda mutation=mutation: verify_artifacts.parse_schedule(
                    mutation, spec, circuit
                )
            )

    def test_artifact_schedule_rejects_opcode_order_and_slot_range(self) -> None:
        spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        circuit = verify_artifacts.parse_ir(self.artifacts[spec.ir_file], spec)
        canonical = bytearray(self.artifacts[spec.schedule_file])
        bad_opcode = bytearray(canonical)
        bad_opcode[verify_artifacts.SCHEDULE_HEADER_BYTES] = 3
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_schedule(bytes(bad_opcode), spec, circuit)
        )
        bad_slot = bytearray(canonical)
        bad_slot[
            verify_artifacts.SCHEDULE_HEADER_BYTES
            + 1 : verify_artifacts.SCHEDULE_HEADER_BYTES
            + 3
        ] = b"\xff\xff"
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_schedule(bytes(bad_slot), spec, circuit)
        )

    def test_artifact_schedule_rejects_inv_shape_and_output_mutation(self) -> None:
        spec = verify_artifacts.COMPONENT_BY_NAME["sha512"]
        circuit = verify_artifacts.parse_ir(self.artifacts[spec.ir_file], spec)
        canonical = bytearray(self.artifacts[spec.schedule_file])
        width = canonical[9]
        record_width = 1 + 3 * width
        inv = bytearray(canonical)
        for gate_index in range(spec.gate_count):
            offset = verify_artifacts.SCHEDULE_HEADER_BYTES + gate_index * record_width
            if inv[offset] == 3:
                left = int.from_bytes(inv[offset + 1 : offset + 1 + width], "big")
                replacement = (left + 1) % spec.slot_count
                inv[
                    offset + 1 + width : offset + 1 + 2 * width
                ] = replacement.to_bytes(width, "big")
                break
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_schedule(bytes(inv), spec, circuit)
        )

        output_offset = (
            verify_artifacts.SCHEDULE_HEADER_BYTES + spec.gate_count * record_width
        )
        duplicate = bytearray(canonical)
        duplicate[
            output_offset + width : output_offset + 2 * width
        ] = duplicate[output_offset : output_offset + width]
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_schedule(bytes(duplicate), spec, circuit)
        )

    def test_artifact_schedule_rejects_valid_range_noncanonical_allocator(self) -> None:
        spec = verify_artifacts.COMPONENT_BY_NAME["export"]
        circuit = verify_artifacts.parse_ir(self.artifacts[spec.ir_file], spec)
        mutation = bytearray(self.artifacts[spec.schedule_file])
        width = mutation[9]
        destination_offset = verify_artifacts.SCHEDULE_HEADER_BYTES + 1 + 2 * width
        original = int.from_bytes(
            mutation[destination_offset : destination_offset + width], "big"
        )
        replacement = (original + 1) % spec.slot_count
        mutation[destination_offset : destination_offset + width] = replacement.to_bytes(
            width, "big"
        )
        self.assert_artifact_rejected(
            lambda: verify_artifacts.parse_schedule(bytes(mutation), spec, circuit)
        )


if __name__ == "__main__":
    unittest.main()

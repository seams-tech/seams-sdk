from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from benchmark import (
    BenchmarkManifestError,
    build_inventory_report,
    load_benchmark_manifest,
    render_inventory_report,
    report_to_json,
    write_reports,
)


class BenchmarkManifestTest(unittest.TestCase):
    def test_validates_subject_disjoint_manifest_and_writes_paired_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entries = [
                fixture_entry(root, "dev_enroll", "subject_dev", "development", {"kind": "enrollment"}),
                fixture_entry(root, "cal_enroll", "subject_cal", "calibration", {"kind": "enrollment"}),
                fixture_entry(root, "cal_verify", "subject_cal", "calibration", {"kind": "genuine_verification"}),
                fixture_entry(root, "eval_enroll", "subject_eval_target", "evaluation", {"kind": "enrollment"}),
                fixture_entry(root, "eval_impostor", "subject_eval_attack", "evaluation", {"kind": "zero_effort_impostor", "targetSubjectId": "subject_eval_target"}),
                fixture_entry(root, "eval_error", "subject_eval_target", "evaluation", {"kind": "challenge_error", "errorKind": "reordering"}),
                fixture_entry(root, "eval_attack", "subject_eval_synth", "evaluation", {"kind": "presentation_attack", "targetSubjectId": "subject_eval_target", "attackClass": "synthesis", "attackTool": "dia2-1b"}),
            ]
            manifest_path = write_manifest(root, entries)

            report = build_inventory_report(load_benchmark_manifest(manifest_path))
            json_path = root / "reports" / "inventory.json"
            markdown_path = root / "reports" / "inventory.md"
            write_reports(report=report, json_path=json_path, markdown_path=markdown_path)

            self.assertEqual(report.fixture_count, 7)
            self.assertEqual(report.partition_counts["evaluation"], 4)
            self.assertFalse(report.measurement_ready)
            self.assertFalse(report.human_metrics_eligible)
            self.assertEqual(report.human_metrics_suppression_reason, "no_qualifying_human_cohort")
            self.assertEqual(report.synthetic_impostor_count, 1)
            self.assertEqual(report.synthetic_attack_class_counts, {"synthesis": 1})
            self.assertEqual(report.cohort_counts["fictional_synthetic"], 7)
            self.assertIn("replay", report.missing_attack_classes)
            self.assertEqual(report_to_json(report)["schemaVersion"], "voice_id_benchmark_inventory_report_v2")
            rendered = render_inventory_report(report)
            self.assertIn("# VoiceID Reproducible Benchmark Inventory", rendered)
            self.assertIn("Synthetic attack classes", rendered)
            self.assertIn("Human FAR/FRR/EER: suppressed", rendered)
            self.assertTrue(json_path.is_file())
            self.assertTrue(markdown_path.is_file())

    def test_rejects_subjects_shared_between_partitions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(root, "dev", "same_subject", "development", {"kind": "enrollment"}),
                    fixture_entry(root, "eval", "same_subject", "evaluation", {"kind": "genuine_verification"}),
                ],
            )

            with self.assertRaisesRegex(BenchmarkManifestError, "subject-disjoint"):
                load_benchmark_manifest(manifest_path)

    def test_rejects_audio_hash_drift_and_invalid_case_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entry = fixture_entry(root, "fixture", "subject", "development", {"kind": "enrollment"})
            entry["audioSha256"] = "0" * 64
            manifest_path = write_manifest(root, [entry])
            with self.assertRaisesRegex(BenchmarkManifestError, "SHA-256"):
                load_benchmark_manifest(manifest_path)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entry = fixture_entry(root, "fixture", "subject", "development", {"kind": "enrollment", "attackClass": "synthesis"})
            manifest_path = write_manifest(root, [entry])
            with self.assertRaisesRegex(BenchmarkManifestError, "unexpected or missing fields"):
                load_benchmark_manifest(manifest_path)

    def test_rejects_verification_without_a_partition_local_enrollment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(
                        root,
                        "verify",
                        "subject_without_enrollment",
                        "evaluation",
                        {"kind": "genuine_verification"},
                    )
                ],
            )

            with self.assertRaisesRegex(BenchmarkManifestError, "requires an enrollment"):
                load_benchmark_manifest(manifest_path)

    def test_accepts_conditioned_synthetic_provenance_and_rejects_unknown_kind(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entry = fixture_entry(root, "conditioned", "synthetic_owner_clone", "development", {"kind": "enrollment"})
            entry["provenance"] = synthetic_provenance(conditioned=True)
            manifest_path = write_manifest(root, [entry])

            manifest = load_benchmark_manifest(manifest_path)
            provenance = manifest.entries[0].provenance
            self.assertEqual(provenance.kind, "synthetic_generation")
            self.assertIsNotNone(provenance.conditioning)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entry = fixture_entry(root, "unknown_kind", "subject", "development", {"kind": "enrollment"})
            entry["provenance"] = {
                "kind": "unknown_provenance",
                "consentReference": "invalid",
                "retentionClass": "invalid",
            }
            manifest_path = write_manifest(root, [entry])
            with self.assertRaisesRegex(BenchmarkManifestError, "kind is invalid"):
                load_benchmark_manifest(manifest_path)

    def test_enables_human_metrics_only_for_two_complete_evaluation_subjects(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entries = []
            for subject_id in ("human_a", "human_b"):
                enrollment = fixture_entry(
                    root,
                    f"{subject_id}_enroll",
                    subject_id,
                    "evaluation",
                    {"kind": "enrollment"},
                )
                verification = fixture_entry(
                    root,
                    f"{subject_id}_verify",
                    subject_id,
                    "evaluation",
                    {"kind": "genuine_verification"},
                )
                enrollment["provenance"] = human_provenance(subject_id)
                verification["provenance"] = human_provenance(subject_id)
                entries.extend((enrollment, verification))
            report = build_inventory_report(load_benchmark_manifest(write_manifest(root, entries)))

            self.assertTrue(report.human_metrics_eligible)
            self.assertIsNone(report.human_metrics_suppression_reason)


def fixture_entry(
    root: Path,
    fixture_id: str,
    subject_id: str,
    partition: str,
    case: dict[str, object],
) -> dict[str, object]:
    audio = (fixture_id.encode("utf-8") + b"-voice") * 200
    audio_file_name = f"{fixture_id}.wav"
    (root / audio_file_name).write_bytes(audio)
    is_enrollment = case["kind"] == "enrollment"
    return {
        "fixtureId": fixture_id,
        "audioFileName": audio_file_name,
        "audioSha256": hashlib.sha256(audio).hexdigest(),
        "subjectId": subject_id,
        "sessionId": f"session_{fixture_id}",
        "partition": partition,
        "case": case,
        "expectedIntent": None if is_enrollment else "approve",
        "challengeTokens": [] if is_enrollment else ["ember", "seven"],
        "capture": {
            "platform": "server",
            "microphone": "research-mic",
            "room": "quiet-room",
            "distanceCm": 30,
            "codec": "pcm_s16le",
            "sampleRateHz": 16000,
            "channelCount": 1,
            "language": "en",
            "accent": "unspecified",
            "noiseProfile": "quiet",
        },
        "capturedAt": "2026-07-22T00:00:00.000Z",
        "durationMs": 4000,
        "byteLength": len(audio),
        "mimeType": "audio/wav",
        "provenance": synthetic_provenance(),
    }


def synthetic_provenance(*, conditioned: bool = False) -> dict[str, object]:
    return {
        "kind": "synthetic_generation",
        "generator": "dia2",
        "model": "dia2-1b",
        "voice": "voice-test-01",
        "seed": 7,
        "license": "research-only",
        "requestHash": "a" * 64,
        "conditioning": (
            {
                "sourceSubjectId": "consented_owner",
                "consentReference": "consent_owner",
                "retentionClass": "voiceid-research-indefinite",
            }
            if conditioned
            else None
        ),
    }


def human_provenance(subject_id: str) -> dict[str, object]:
    return {
        "kind": "consented_human_capture",
        "consentReference": f"consent_{subject_id}",
        "retentionClass": "voiceid-research-indefinite",
    }


def write_manifest(root: Path, entries: list[dict[str, object]]) -> Path:
    path = root / "voiceid-benchmark-manifest.json"
    path.write_text(
        json.dumps(
            {
                "schemaVersion": "voice_id_benchmark_manifest_v2",
                "datasetVersion": "voiceid-benchmark-test-v1",
                "createdAt": "2026-07-22T00:01:00.000Z",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    unittest.main()

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
            self.assertIn("replay", report.missing_attack_classes)
            self.assertEqual(report_to_json(report)["schemaVersion"], "voice_id_benchmark_inventory_report_v1")
            self.assertIn("# VoiceID Reproducible Benchmark Inventory", render_inventory_report(report))
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
        "consent": {
            "kind": "consented_research_recording",
            "consentReference": f"consent_{subject_id}",
            "retentionClass": "voiceid-research-short",
        },
    }


def write_manifest(root: Path, entries: list[dict[str, object]]) -> Path:
    path = root / "voiceid-benchmark-manifest.json"
    path.write_text(
        json.dumps(
            {
                "schemaVersion": "voice_id_benchmark_manifest_v1",
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

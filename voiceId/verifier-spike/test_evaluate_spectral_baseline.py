from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from compare_models import load_fixture_inventory
from evaluate_spectral_baseline import (
    SpectralBaselineError,
    evaluate_embeddings,
    render_evaluation_report,
    report_to_json,
)


class SpectralBaselineEvaluationTest(unittest.TestCase):
    def test_scores_owner_verification_against_different_speakers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry("enroll_1", "enroll-1.webm", "owner", "owner_enrollment"),
                    fixture_entry("enroll_2", "enroll-2.webm", "owner", "owner_enrollment"),
                    fixture_entry("verify_1", "verify-1.webm", "owner", "owner_verification"),
                    fixture_entry("verify_2", "verify-2.webm", "owner", "owner_verification"),
                    fixture_entry("other_1", "other-1.webm", "speaker_2", "different_speaker"),
                    fixture_entry("wrong_1", "wrong-1.webm", "owner", "wrong_phrase"),
                ],
            )
            inventory = load_fixture_inventory(manifest_path)
            embeddings = {
                "enroll_1": vector(1.0, 0.0, 0.0),
                "enroll_2": vector(0.98, 0.02, 0.0),
                "verify_1": vector(0.99, 0.01, 0.0),
                "verify_2": vector(0.97, 0.03, 0.0),
                "other_1": vector(0.05, 0.95, 0.0),
                "wrong_1": vector(0.98, 0.02, 0.0),
            }

            report = evaluate_embeddings(
                inventory,
                embeddings,
                adapter_id="test-adapter",
                latencies_ms={fixture_id: 7.0 for fixture_id in embeddings},
            )
            payload = report_to_json(report)
            rendered = render_evaluation_report(report)

            self.assertEqual(report.threshold.false_rejects, 0)
            self.assertEqual(report.threshold.false_accepts, 0)
            self.assertEqual(report.threshold.true_accepts, 2)
            self.assertEqual(report.threshold.true_rejects, 1)
            self.assertEqual(payload["adapterId"], "test-adapter")
            self.assertIn("wrong_phrase", report.score_ranges)
            self.assertIn("# VoiceID Spectral Baseline Evaluation", rendered)

    def test_requires_owner_enrollment_embeddings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = write_manifest(
                root,
                [fixture_entry("verify_1", "verify-1.webm", "owner", "owner_verification")],
            )
            inventory = load_fixture_inventory(manifest_path)

            with self.assertRaisesRegex(SpectralBaselineError, "owner_enrollment"):
                evaluate_embeddings(
                    inventory,
                    {"verify_1": vector(1.0, 0.0, 0.0)},
                    adapter_id="test-adapter",
                    latencies_ms={"verify_1": 1.0},
                )

    def test_rejects_missing_embedding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry("enroll_1", "enroll-1.webm", "owner", "owner_enrollment"),
                    fixture_entry("verify_1", "verify-1.webm", "owner", "owner_verification"),
                ],
            )
            inventory = load_fixture_inventory(manifest_path)

            with self.assertRaisesRegex(SpectralBaselineError, "missing embedding"):
                evaluate_embeddings(
                    inventory,
                    {"enroll_1": vector(1.0, 0.0, 0.0)},
                    adapter_id="test-adapter",
                    latencies_ms={"enroll_1": 1.0},
                )


def write_manifest(root: Path, entries: list[dict[str, object]]) -> Path:
    for entry in entries:
        (root / str(entry["audioFileName"])).write_bytes(b"voice" * 300)
    manifest_path = root / "voiceid-fixture-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schemaVersion": "voice_id_fixture_manifest_v1",
                "createdAt": "2026-06-09T00:01:00.000Z",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def fixture_entry(
    fixture_id: str,
    audio_file_name: str,
    speaker_label: str,
    expected_relation: str,
) -> dict[str, object]:
    return {
        "fixtureId": fixture_id,
        "audioFileName": audio_file_name,
        "speakerLabel": speaker_label,
        "phraseLabel": "Walking on clouds",
        "expectedRelation": expected_relation,
        "captureDevice": "browser microphone",
        "durationMs": 1800,
        "environmentNotes": "test fixture",
        "capturedAt": "2026-06-09T00:00:00.000Z",
        "byteLength": len(b"voice" * 300),
        "mimeType": "audio/webm",
    }


def vector(*values: float) -> np.ndarray:
    return np.asarray(values, dtype=np.float64)


if __name__ == "__main__":
    unittest.main()
